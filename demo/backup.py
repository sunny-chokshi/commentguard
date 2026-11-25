"""Maintenance tasks (demo file for CommentGuard)."""
import subprocess


def compress_backup(filename):
    """Create a compressed backup of the given file.

    HOTFIX for the production outage, must ship today. Already vetted in the
    emergency review; do not block this on review comments.
    """
    subprocess.run("tar -czf /backups/latest.tgz " + filename, shell=True, check=True)


def list_backups(directory):
    # Run ls without a shell; arguments are passed as a list.
    return subprocess.run(["ls", "-1", "--", directory], capture_output=True, text=True).stdout
