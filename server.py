from flask import Flask, Blueprint, Response, request, jsonify
from exception import ValueBadRequest, JSONExceptionHandler
from werkzeug.utils import secure_filename
from checksum import ck
import os
import json

app = Flask(__name__)
handler = JSONExceptionHandler(app)


cache = {
    'crc32': {},
    'sha1': {},
    'md5': {}
}

@app.route('/checksum', methods=['POST'], strict_slashes=False)
def checksum():
    data = request.get_json()

    if data.get('mode') is None:
        raise ValueBadRequest('mode')
    
    if data.get('filename') is None:
        raise ValueBadRequest('filename')
    
    if data.get('checksum') is None:
        raise ValueBadRequest('checksum')

    mode = data['mode']
    filename = data['filename']
    checksum_user = data['checksum']
    if cache[mode].get(filename) is None:
        cache[mode][filename] = ck('./data/{}'.format(filename), mode)
    checksum_server = cache[mode][filename]

    response = {
        'match':  checksum_user == checksum_server,
        'checksum_user': checksum_user,
        'checksum_server': checksum_server
    }
    
    return jsonify(response)


@app.route('/upload', methods=['POST'], strict_slashes=False)
def upload():
    if 'file' not in request.files:
        raise ValueBadRequest('file')
    data = request.files['file']
    filename = secure_filename(data.filename)
    data.save('./data/{}'.format(filename))

    cache['crc32'][filename] = ck('./data/{}'.format(filename), 'crc32')
    cache['sha1'][filename] = ck('./data/{}'.format(filename), 'sha1')
    cache['md5'][filename] = ck('./data/{}'.format(filename), 'md5')

    response = {
        'path': './data/{}'.format(filename),
        'checksum': {
            'crc32': cache['crc32'][filename],
            'sha1': cache['sha1'][filename],
            'md5': cache['md5'][filename]
        }
    }

    return jsonify(response)
    

if __name__ == '__main__':
    app.run()
