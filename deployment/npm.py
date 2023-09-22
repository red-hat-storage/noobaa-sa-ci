import logging
from pynpm import NPMPackage

log = logging.getLogger(__name__)


class NPM(object):
    """
    NPM class
    """

    def __init__(self, package):
        """
        Initializes the necessary variables needed for NPM

        Args:
            package (str): Path to package.json

        """
        self.pkg = NPMPackage(package)

    def run_script(self, cmd, args=None, wait=True):
        """
        Runs the command with npm

        Args:
            cmd (str): command to execute as part of npm
            args (tuple): arguments to pass to run_scrit
               e.g: ('--', 'drive1', '--port', '9991')
            wait (bool): If True, npm will wait till command is completed

        Returns:
            object: subprocess.Popen object

        """
        log.info(f"executing 'npm run {cmd}'")
        if args:
            return self.pkg.run_script(cmd, *args, wait=wait)
        return self.pkg.run_script(cmd, wait=wait)
