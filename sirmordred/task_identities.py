#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2019 Bitergia
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# Authors:
#     Luis Cañas-Díaz <lcanas@bitergia.com>
#     Alvaro del Castillo <acs@bitergia.com>
#     Quan Zhou <quan@bitergia.com>
#

import base64
import gzip
import hashlib
import json
import logging
import shutil
import tempfile
import time

from datetime import datetime

from sirmordred.task import Task
from sirmordred.task_manager import TasksManager
from sortinghat.cli.client import (SortingHatClient,
                                   SortingHatClientError,
                                   SortingHatSchema)

from sgqlc.operation import Operation

from grimoire_elk.elk import load_identities
from grimoire_elk.enriched.sortinghat_gelk import SortingHat

SLEEP_TIME = 5

logger = logging.getLogger(__name__)


def get_file_hash(filepath):
    """Generate hash based on the file content

    Read the content of a JSON file, remove all no alphanumeric
    characters, sort the remaining characters and create a hash from them.

    :param filepath: local path of the file to hash
    :return: content hash
    """
    with open(filepath, 'r') as f:
        content = f.read()

    json_content = json.loads(content)
    # Remove the attribute time for identities file, since its value changes
    # any time the file is generated
    json_content.pop('time', None)
    json_dump = json.dumps(json_content)

    digest_content = "".join([c if c.isalnum() else "" for c in sorted(json_dump)]).strip()
    hash_object = hashlib.sha256()
    hash_object.update(digest_content.encode('utf-8'))
    return hash_object.hexdigest()


class TaskIdentitiesCollection(Task):
    """ Class aimed to get identites from raw data """

    def __init__(self, config, load_ids=True):
        super().__init__(config)

        self.load_ids = load_ids  # Load identities from raw index

    def execute(self):

        # FIXME this should be called just once
        # code = 0 when command success
        # code = Init(**self.sh_kwargs).run(self.db_sh, '--reuse')

        if not self.backend_section:
            logger.error("Backend not configured in TaskIdentitiesCollection %s", self.backend_section)
            return

        backend_conf = self.config.get_conf()[self.backend_section]

        if 'collect' in backend_conf and not backend_conf['collect']:
            logger.info("Don't load ids from a backend without collection %s", self.backend_section)
            return

        if self.load_ids:
            logger.info("[%s] Gathering identities from raw data", self.backend_section)
            enrich_backend = self._get_enrich_backend()
            ocean_backend = self._get_ocean_backend(enrich_backend)
            load_identities(ocean_backend, enrich_backend)
            # FIXME get the number of ids gathered


class TaskIdentitiesMerge(Task):
    """ Task for processing identities in SortingHat """

    def __init__(self, conf):
        super().__init__(conf)
        self.last_autorefresh = datetime.utcnow()  # Last autorefresh date

    def is_backend_task(self):
        return False

    def __get_uuids_from_profile_name(self, profile_name):
        """ Get the uuid for a profile name """

        def fetch_mk(entities, name):
            mks = []
            for e in entities:
                mk = e['mk']
                if e['profile']['name'] == name:
                    mks.append(mk)

            return mks

        args = {
            'page': 1,
            'page_size': 10
        }
        try:
            op = Operation(SortingHatSchema.Query)
            op.individuals(**args)
            individual = op.individuals().entities()
            individual.mk()
            individual.profile().name()
            page_info = op.individuals().page_info()
            page_info.has_next()
            result = self.client.execute(op)
            entities = result['data']['individuals']['entities']
            mks = fetch_mk(entities, profile_name)
            has_next = result['data']['individuals']['pageInfo']['hasNext']
            while has_next:
                page = args['page']
                args['page'] = page + 1
                op = Operation(SortingHatSchema.Query)
                op.individuals(**args)
                individual = op.individuals().entities()
                individual.mk()
                individual.profile().name()
                page_info = op.individuals().page_info()
                page_info.has_next()
                result = self.client.execute(op)
                entities = result['data']['individuals']['entities']
                mks.extend(fetch_mk(entities, profile_name))
                has_next = result['data']['individuals']['pageInfo']['hasNext']
        except SortingHatClientError as e:
            logger.error("[sortinghat] Error get uuid from profile name {}: {}".
                         format(profile_name, e.errors[0]['message']))

        return mks

    def do_affiliate(self):
        mks = SortingHat.unique_identities(self.client)
        args = {
            "uuids": mks
        }
        try:
            op = Operation(SortingHatSchema.SortingHatMutation)
            op.affiliate(**args).job_id
            result = self.client.execute(op)
            id = result['data']['affiliate']['jobId']
            logger.info("[sortinghat] Affiliate job id: {}".format(id))
            wait = self.check_job(id)
            while wait:
                time.sleep(SLEEP_TIME)
                wait = self.check_job(id)
        except SortingHatClientError as e:
            logger.error("[sortinghat] Error affiliate: {}".format(e.errors[0]['message']))

        return

    def do_autogender(self):
        return None

    def do_autoprofile(self, sources):
        return None

    def do_unify(self, kwargs):
        mks = SortingHat.unique_identities(self.client)
        try:
            op = Operation(SortingHatSchema.SortingHatMutation)
            args = {
                'criteria': [kwargs['matching']],
                'source_uuids': mks
            }
            op.unify(**args).job_id
            result = self.client.execute(op)
            id = result['data']['unify']['jobId']
            logger.info("[sortinghat] Unify job id: {}".format(id))
            wait = self.check_job(id)
            while wait:
                time.sleep(SLEEP_TIME)
                wait = self.check_job(id)
        except SortingHatClientError as e:
            logger.error("[sortinghat] Error unify: {}".format(e.errors[0]['message']))

        return

    def check_job(self, id):
        args = {
            "job_id": id
        }
        try:
            op = Operation(SortingHatSchema.Query)
            jobid = op.job(**args)
            jobid.status()
            jobid.errors()
            result = self.client.execute(op)
            job = result['data']['job']
            wait = True
            if job['errors']:
                wait = False
                raise job['errors']
            if job['status'] == 'finished' or job['status'] == 'failed':
                wait = False
        except SortingHatClientError as e:
            logger.error("[sortinghat] Error check job ID {}: {}".format(id, e.errors[0]['message']))

        return wait

    def execute(self):

        # ** START SYNC LOGIC **
        # Check that enrichment tasks are not active before loading identities
        while True:
            time.sleep(1)  # check each second if the task could start
            with TasksManager.IDENTITIES_TASKS_ON_LOCK:
                with TasksManager.NUMBER_ENRICH_TASKS_ON_LOCK:
                    enrich_tasks = TasksManager.NUMBER_ENRICH_TASKS_ON
                    logger.debug("[unify] Enrich tasks active: %i", enrich_tasks)
                    if enrich_tasks == 0:
                        # The load of identities can be started
                        TasksManager.IDENTITIES_TASKS_ON = True
                        break
        #  ** END SYNC LOGIC **

        cfg = self.config.get_conf()

        uuids_refresh = []

        for algo in cfg['sortinghat']['matching']:
            if not algo:
                # cfg['sortinghat']['matching'] is an empty list
                logger.debug('Unify not executed because empty algorithm')
                continue
            kwargs = {'matching': algo, 'fast_matching': True,
                      'strict_mapping': cfg['sortinghat']['strict_mapping']}
            logger.info("[sortinghat] Unifying identities using algorithm %s",
                        kwargs['matching'])
            self.do_unify(kwargs)

        if not cfg['sortinghat']['affiliate']:
            logger.debug("Not doing affiliation")
        else:
            # Global enrollments using domains
            logger.info("[sortinghat] Executing affiliate")
            self.do_affiliate()

        if 'autoprofile' not in cfg['sortinghat'] or \
                not cfg['sortinghat']['autoprofile'][0]:
            logger.info("[sortinghat] Autoprofile not configured. Skipping.")
        else:
            logger.info("[sortinghat] Executing autoprofile for sources: %s",
                        cfg['sortinghat']['autoprofile'])
            sources = cfg['sortinghat']['autoprofile']
            self.do_autoprofile(sources)

        if 'autogender' not in cfg['sortinghat'] or \
                not cfg['sortinghat']['autogender']:
            logger.info("[sortinghat] Autogender not configured. Skipping.")
        else:
            logger.info("[sortinghat] Executing autogender")
            self.do_autogender()

        with TasksManager.IDENTITIES_TASKS_ON_LOCK:
            TasksManager.IDENTITIES_TASKS_ON = False
