# systembackup

A tool to back up systems, based on rclone. Backups are compressed as
`.tar.gz` archives and encrypted with `gpg` before being uploaded to the
remote.

# Usage

All commands are assumed to be run as root.

* Clone this repository and move into the project directory.

```bash
git clone https://github.com/boolean-world/systembackup.git
cd systembackup
```

* Start the interactive setup and follow the instructions. Be sure to add one
(and only one) remote through rclone. (You'll be prompted to do so right here.)

```bash
./systembackup.sh setup
```

* Create a backup and upload it with:

```bash
./systembackup.sh backup
```

* Later on, you can download a backup and decrypt it with:

```bash
./systembackup.sh decrypt {Backup File}
```

The result will be a `.tar.gz` file, which you can extract or view with the
`tar` command (you may need to use the `-z` flag.)

# License

https://opensource.org/licenses/MIT
