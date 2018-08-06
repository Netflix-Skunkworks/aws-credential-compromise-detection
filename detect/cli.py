import logging
import os
import yaml

import click
import click_log
from click.exceptions import UsageError

from detect import log
from detect.__about__ import __version__
from detect.cloudtrail import detect_off_instance_cloudtrail


click_log.basic_config(log)

class YAML(click.ParamType):
    name = 'yaml'

    def convert(self, value, param, ctx):
        try:
            with open(value, 'rb') as f:
                return yaml.safe_load(f.read())
        except (IOError, OSError) as e:
            self.fail('Could not open file: {0}'.format(value))


@click.command()
@click_log.simple_verbosity_option(log)
@click.option('--config', type=YAML(), help='Configuration file to use.')
@click.option('--directory', type=str, help='Path to directory with CloudTrail files', required=True)
@click.version_option(version=__version__)
def cli(config, directory):
    """Detect off instance key usage"""
    log.info('Detecting AWS Key Usage off instance...')

    if not os.path.exists(directory):
        log.fatal('Invalid Directory Path')

    files = []
    for cloudtrail_file in os.listdir(directory):
        files.append(os.path.join(directory, cloudtrail_file))

    if not config:
        config = {}

    api_calls_recorded = detect_off_instance_cloudtrail(config, files)


if __name__ == '__main__':
    try:
        cli()
    except KeyboardInterrupt:
        logging.debug("Exiting due to KeyboardInterrupt...")

