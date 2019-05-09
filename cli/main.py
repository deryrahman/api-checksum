from checksum import ck
import argparse


def main(args):
    mode = args.mode
    path = args.path
    filename = path.split('/')[-1]

    checksum = ck(path, mode)
    print('[CHECKSUM]:', checksum)
    print('[URL]:', 'http://localhost:5000/checksum?mode={}&filename={}&checksum={}'.format(mode, filename, checksum))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('--mode',
                        type=str,
                        default='crc32')
    parser.add_argument('--path',
                        type=str,
                        default='./user_data/1234.jpg')
    args = parser.parse_args()

    main(args)
