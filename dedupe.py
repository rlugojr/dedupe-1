#!/usr/bin/python3
import argparse
from collections import defaultdict
import hashlib
import json
import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)

def hash_file(path):
    log.debug('Reading %s...', path)
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(1024*1024)
            if not chunk:
                break
            h.update(chunk)
    
    return h.hexdigest()

def load_cache(data, cache, dir_path):
    res = cache.copy()

    for fileinfo in data:
        p = dir_path / fileinfo['path']
        if not p.is_file():
            continue
    
        st = p.stat()
        if (st.st_size != fileinfo['st_size']) or (st.st_mtime != fileinfo['st_mtime']):
            continue
        
        # File exists, and size and mtime haven't changed; assume the file's
        # contents are the same.
        fileinfo['path'] = str(p)
        res[str(p)] = fileinfo
    
    return res

def cache_format(files_by_hash, dir_path):
    res = []
    for l in files_by_hash.values():
        for x in l:
            info = x.copy()
            info['path'] = os.path.relpath(info['path'], dir_path)
            res.append(info)

    return res


def update_dict_list(target, update_from):
    for k, l in update_from.items():
        for x in l:
            target[k].append(x)

def get_dir_hashes(path, cached, top_level=False):
    cache_file = path / '.dedupe_cache.json'
    if cache_file.is_file():
        with cache_file.open('r') as f:
            cached = load_cache(json.load(f), cached, path)
    
    files_by_hash = defaultdict(list)
    dirs_by_hash = defaultdict(list)
    
    contents = []
    
    for file in path.iterdir():
        p = os.path.normpath(str(file))
        if file.is_dir():
            subdir_hash, sd_dirs, sd_files = get_dir_hashes(file, cached)
            contents.append(('D', file.name, subdir_hash))
            update_dict_list(dirs_by_hash, sd_dirs)
            update_dict_list(files_by_hash, sd_files)
            continue
        
        if file.name == '.dedupe_cache.json':
            continue
        
        if p in cached:
            info = cached[p]
            file_hash = info['hash']
        else:
            st = os.stat(p)
            file_hash = hash_file(p)
            info = {
                'path': p,
                'st_size': st.st_size,
                'st_mtime': st.st_mtime,
                'hash': file_hash,
            }
        
        contents.append(('F', file.name, file_hash))
        
        files_by_hash[file_hash].append(info)
    
    dir_hash = hashlib.sha256(b'DEDUPE_DIR_LISTING\0')
    for record in sorted(contents):
        # 1F: unit separator, 1E: record separator
        s = '\x1f'.join(record) + '\x1e'
        dir_hash.update(s.encode('utf-8', 'surrogateescape'))

    if cache_file.is_file() or top_level:
        with cache_file.open('w') as f:
            json.dump(cache_format(files_by_hash, str(path)), f, indent=1)

    if contents:
        # Don't bother storing hashes for empty directories.
        dirs_by_hash[dir_hash.hexdigest()].append(path)
    return dir_hash.hexdigest(), dirs_by_hash, files_by_hash

def in_duplicated_dirs(files, duplicated_dirs):
    f0 = Path(files[0])
    for d in f0.parents:
        if d in duplicated_dirs:
            rel_path = f0.relative_to(d)
            matching_dirs = duplicated_dirs[d]
            break
    else:
        return False
    
    matching_paths = {Path(d, rel_path) for d in matching_dirs}
    
    return all(Path(f) in matching_paths for f in files[1:])

_home_dir = os.path.expanduser('~').rstrip('/\\')
def compress_user(p):
    p = str(p)
    if p.startswith(_home_dir):
        return '~' + p[len(_home_dir):]
    return p

def print_duplicates(dirs_by_hash, files_by_hash):
    duplicated_dirs = {}
    for l in dirs_by_hash.values():
        if len(l) < 2:
            continue
        for d in l:
            duplicated_dirs[d] = l
    
    for l in dirs_by_hash.values():
        if len(l) < 2:
            continue
        if in_duplicated_dirs(l, duplicated_dirs):
            continue
        print(compress_user(l[0]), '(Directory)')
        for d in l[1:]:
            print(compress_user(d))
        print()
    
    for l in files_by_hash.values():
        if len(l) < 2:
            continue
        if l[0]['st_size'] == 0:
            # Empty files aren't interesting
            continue
        if in_duplicated_dirs([f['path'] for f in l], duplicated_dirs):
            continue
        for f in l:
            print(compress_user(f['path']))
        print()

def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('directory', nargs='+')
    args = ap.parse_args(argv)
    
    files_by_hash = defaultdict(list)
    dirs_by_hash = defaultdict(list)    
    
    for d in args.directory:
        print('Scanning %s...' % d)
        _, dirs_to_add, files_to_add = get_dir_hashes(Path(d).resolve(), {},
                                                      top_level=True)
    
        update_dict_list(dirs_by_hash, dirs_to_add)
        update_dict_list(files_by_hash, files_to_add)
    
    print()
    print_duplicates(dirs_by_hash, files_by_hash)

if __name__ == '__main__':
    main()
    
            