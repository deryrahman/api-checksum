from flask import Flask, request, jsonify
from flask_autoindex import AutoIndex
from exception import ValueBadRequest, JSONExceptionHandler
from werkzeug.utils import secure_filename
from checksum import ck

app = Flask(__name__)
AutoIndex(app, browse_root='./data')
JSONExceptionHandler(app)


cache = {
    'crc32': {},
    'sha1': {},
    'md5': {}
}


@app.route('/checksum', methods=['GET'], strict_slashes=False)
def checksum():
    mode = request.args.get('mode')
    filename = request.args.get('filename')
    checksum_user = request.args.get('checksum')

    if mode is None:
        raise ValueBadRequest('mode')

    if filename is None:
        raise ValueBadRequest('filename')

    if checksum_user is None:
        raise ValueBadRequest('checksum')

    if cache[mode].get(filename) is None:
        cache[mode][filename] = ck('./data/{}'.format(filename), mode)
    checksum_server = cache[mode][filename]

    response = {
        'match': checksum_user == checksum_server,
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
    app.run(port=5000)
