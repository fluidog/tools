#! /bin/env python3

import logging

import pickle
import re
import git
from git.repo import Repo
import requests
import os
import functools
import threading

import concurrent.futures

MAIN_LINE = ('/root/workspace/kernel/linux/', 'master')
CVE_ORIGIN_URL = 'https://raw.githubusercontent.com/nluedtke/linux_kernel_cves/master/data/CVEs.txt'

class Cve(object):
    def __init__(self, id, breaks_sha, fixes_sha, versions):
        self.id = id
        self.breaks_sha = breaks_sha
        self.fixes_sha = fixes_sha
        self.versions = versions
        self._other_branch_fixes_sha = []
     
    def commit_sha(self, branch=None):
        if not re.match(r'^[0-9a-fA-F]*$', self.fixes_sha):
            return None
   
        branch = branch if branch else MAIN_LINE
        if branch == MAIN_LINE:
            return self.fixes_sha
            
        for (_branch, sha) in self._other_branch_fixes_sha:
            if branch == _branch:
                return sha

        with Repo(branch[0]) as repo:
            commmits = repo.iter_commits(branch[1], paths=self.commit_patch_path()[0])
            for cmt in commmits:
                if cmt.summary == self.commit_summary():
                    self._other_branch_fixes_sha.append((branch, cmt.hexsha))
                    return cmt.hexsha
        self._other_branch_fixes_sha.append((branch, None))
        return None

    def is_fixed(self, branch=None):
        return True if self.commit_sha(branch) else False

    @staticmethod
    def cache(func):
        data = {}
        lock = threading.Lock()
        @functools.wraps(func)
        def wrapper(*args):
            key = tuple(filter(None, args)) # remove None args
            if key in data:
                return data[key]
            with lock:
                logging.debug('cache miss: %s', key)
                data[key] = func(*args)
            return data[key]
        return wrapper

    # @functools.cache
    @cache  # must be cached
    def commit(self, branch=None):
        if not self.is_fixed(branch):
            return None
        repo = branch[0] if branch and branch[0] else MAIN_LINE[0]
        with Repo(repo) as r:
            return r.commit(self.commit_sha(branch))

    @staticmethod
    def get_commit_attr(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            self = args[0]
            if not self.is_fixed(*args[1:]):
                return None
            result = func(*args, **kwargs)
            self.commit(*args[1:]).repo.close()
            return result
        return wrapper

    @get_commit_attr
    def commit_summary(self, branch=None):
        return self.commit(branch).summary

    @get_commit_attr
    def commit_message(self, branch=None):
        return self.commit(branch).message

    @get_commit_attr
    def commit_author(self, branch=None):
        return self.commit(branch).author

    @get_commit_attr
    def commit_author_date(self, branch=None):
        return self.commit(branch).authored_date
 
    @get_commit_attr
    def commit_author_datetime(self, branch=None):
        return self.commit(branch).authored_datetime.date()

    @get_commit_attr
    def commit_committer(self, branch=None):
        return self.commit(branch).committer

    @get_commit_attr
    def commit_committed_date(self, branch=None):
        return self.commit(branch).committed_date

    @get_commit_attr
    def commit_committed_datetime(self, branch=None):
        return self.commit(branch).committed_datetime.date()

    @get_commit_attr
    def commit_patch(self, branch=None):
        # Only first parent
        parent = self.commit(branch).parents[0] \
            if self.commit(branch).parents else git.NULL_TREE
        return self.commit(branch).diff(parent)

    @get_commit_attr
    def commit_patch_path(self, branch=None):
        """ The path of first patch applied to. """
        return [ patch.b_path for patch in self.commit_patch(branch) ]

class CveDb(object):
    def __init__(self):
        """ All cves if cve_ids is None """
        saved_db = CveDb._restore()
        if saved_db:
            self._cves = saved_db._cves
            return
        self._cves = {}
        self._load_cves()

    def _load_cves(self):
        with requests.get(CVE_ORIGIN_URL) as r:
            origin_cves =r.text

        for line in origin_cves.split('\n'):
            cve_info = re.match(r'^(CVE-\d*-\d*): (\S*) - (\S*) (.*)', line.strip())
            if not cve_info:
                cve_info =  re.match(r'^(CVE-\d*-\d*): (.*)', line.strip())
                if not cve_info:
                    logging.warning('Can not parse cve info from: %s', line)
                    continue
                cve_info = (cve_info.group(1), '(n/a)', '(n/a)', cve_info.group(2))
            else:
                cve_info = cve_info.groups()
            self._cves[cve_info[0]] = Cve(*cve_info)

    def __getitem__(self, cve_id):
        if cve_id in self._cves:
            return self._cves[cve_id]

    def cves(self):
        """ return all cves """
        for cve in self._cves.values():
            yield cve

    def fixed_cves(self, branch=None):
        cves_stack = []

        for cve in self.cves():
            cves_stack.append(cve)
            if len(cves_stack) < os.cpu_count() * 2:
                continue
                
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future_to_cve = { executor.submit(cve.is_fixed, branch): cve
                    for cve in cves_stack }
                for future in concurrent.futures.as_completed(future_to_cve):
                    if not future.result():
                        cves_stack.remove(future_to_cve[future])

            while cves_stack:
                yield cves_stack.pop()

    def save(self):
        cache_file = '/run/kernel-cve-db'
        with open(cache_file, 'wb') as fd:
            pickle.dump(self, fd)
            logging.info('Saved to %s', cache_file)
  
    @staticmethod
    def _restore():
        cache_file = '/run/kernel-cve-db'
        try:
            with open(cache_file, 'rb') as fd:
                logging.info('Restore from cache file!')
                return pickle.load(fd)
        except FileNotFoundError:
            return None



if __name__ == '__main__':
    from rich import print
    from rich.console import Console
    from rich.logging import RichHandler
    from rich.columns import Columns
    from rich.progress import track
    from rich import inspect

   
    logging.basicConfig(format='%(message)s', level=logging.INFO,
        handlers=[RichHandler(log_time_format='[%X]')])

    logging.info('Start')

    db = CveDb()

    logging.info('Create cve datebase complete')

    def get_fixed_cves(branchs):
        def sort_key(branch):
            return lambda cve: (
                cve.commit_committed_date(branch),
                cve.commit_author_date(branch))
        fixed_cves = []

        for branch in branchs:
            cves = [cve for cve in track(
                        db.fixed_cves(branch),
                        description=f'Geting cves from {branch}'
                )]
            cves = sorted(cves, key=sort_key(branch))
            fixed_cves.append(cves)
            logging.info(f'Get {len(cves)} cves from {branch[1]}')
        return fixed_cves
        
    repo_klinux = '/root/workspace/kernel/klinux4.19-zyj'
    branch_kylinos = (repo_klinux, 'kylinos')
    branch_kylinos_zyj = (repo_klinux, 'kylinos-zyj')
    branch_zyj_4_sw = (repo_klinux, 'zyj-4-sw')
    branch_zyj_3 = (repo_klinux, 'zyj-3')

    all_branchs = [MAIN_LINE] + [branch_kylinos, branch_kylinos_zyj, branch_zyj_4_sw, branch_zyj_3]

    fixed_cves_from_branch = dict(zip(all_branchs, get_fixed_cves(all_branchs)))


    # Base branch and branch must be in the same repo.
    def auto_cherry_pick_cves(base_branch, cherry_pick_branch):
        not_fixed_cves = [ cve for cve in 
            fixed_cves_from_branch[base_branch] 
            if cve not in fixed_cves_from_branch[cherry_pick_branch] ]

        with Repo(cherry_pick_branch[0]) as repo:
            cherry_picked_cves = []
            repo.git.checkout(cherry_pick_branch[1],
                B=f'fix-cves-to-{cherry_pick_branch[1]}')
            for cve in not_fixed_cves:
                try:
                    repo.git.cherry_pick(cve.commit_sha(base_branch))
                except git.exc.GitCommandError as e:
                    if e.status == 1:
                        logging.debug('Skiped cherry-pick failed cve: %s', cve.id)
                        repo.git.cherry_pick('--skip')
                else:
                    cherry_picked_cves.append(cve)
        logging.info(f'Cherry-picked {len(cherry_picked_cves)}({len(not_fixed_cves)}) cves from {base_branch} to {cherry_pick_branch}')          
        return cherry_picked_cves         

    base_branch = branch_kylinos
    cherry_pick_branchs = [branch_kylinos_zyj, branch_zyj_4_sw, branch_zyj_3]

    exclude_cve_ids = ['CVE-2021-3347', ]
        # [ 'CVE-2021-3600', 'CVE-2021-3347', 'CVE-2019-19377', 
        # 'CVE-2019-19039', 'CVE-2021-4083', 'CVE-2021-27365', 'CVE-2020-1749', 'CVE-2020-14386' ]
    fixed_cves_from_branch[base_branch] = [ cve for cve in fixed_cves_from_branch[base_branch] if cve.id not in exclude_cve_ids ]
    
    cherry_picked_cves = dict(zip(cherry_pick_branchs, [auto_cherry_pick_cves(base_branch, branch) for branch in cherry_pick_branchs]))

    def export_to_excel():
        import pandas as pd
        logging.info('Begin export to excel')
        all_cves = list(db.cves())

        def cve_base_info(cve):
            return {
                '标识': cve.id,
                '已修复(主线)': cve.is_fixed(),
                '影响版本': cve.versions,
                '摘要' : cve.commit_summary(),
                '作者' : cve.commit_author(),
                '修复日期' : cve.commit_author_datetime(),
                '影响路径' : cve.commit_patch_path(),
                '引入SHA(主线)': cve.breaks_sha,
                '修复SHA(主线)': cve.fixes_sha,
            }
        data = map(lambda cve:cve_base_info(cve), all_cves)
        df = pd.DataFrame(data)

        def cve_fixed_info_from_branch(cve, branch):
            if cve in fixed_cves_from_branch[branch]:
                return (True, cve.commit_committer(branch),
                    cve.commit_committed_datetime(branch),
                    cve.commit_sha(branch),
                )
            return False, None, None, None
        for branch in all_branchs:
            cve_fixed_info = functools.partial(cve_fixed_info_from_branch, branch=branch)
            data = map(cve_fixed_info, all_cves)
            df_new= pd.DataFrame(data, columns=[f'已修复({branch[1]})', '提交者', '提交日期', '提交SHA'])
            df = pd.concat([df, df_new], axis=1)
            logging.info('Append cve fixed info from %s', branch)

        def cve_cherry_pick_info(cve):
            info = []
            for branch in cherry_pick_branchs:
                if cve in cherry_picked_cves[branch]:
                    info.append(branch[1])
            return info if info else None
        data ={'可自动合并': [ cve_cherry_pick_info(cve) for cve in all_cves ]}
        df_new= pd.DataFrame(data)
        df = pd.concat([df, df_new], axis=1)

        df.to_excel('cve.xlsx')

    export_to_excel()

    db.save()
   