#!/bin/bash

USER="$(id -nu)" # May be undefined when running through cron.
selfdir="$(readlink -e "$(dirname "$0")")"
datadir="$selfdir/data"
rclone_config="$datadir/rclone_config"
backup_config="$datadir/config.sh"
lockfile='/tmp/systembackup.lock'

die() {
	echo "$1"
	exit 1
}

escape_str() {
	sed -r "s/[\"'$\`\\(){}; \t\r\f\n]/\\\\&/g"
}

print_help() {
	cat << EOM
Usage: $0 COMMAND
A tool to back up systems, based on rclone.

Supported commands:
 setup     Install dependencies and set up configuration interactively
 backup    Create a backup and upload it
 extract   Extract a backup file
 help      Show this help message
EOM
}

print_command_error() {
	die "Unknown argument '$1', run '$0 help' for usage help."
}

assert_root() {
	if [[ $EUID -ne 0 ]]; then
		die 'This command can be only run as root.'
	fi
}

acquire_mutex() {
	exec 9>$lockfile
	flock -nx 9 || die "An instance of this script is already running."
	mutex_acquired=1
}

release_mutex() {
	if [[ ! -z $mutex_acquired ]]; then
		flock -u 9
	fi
}

get_remote_name() {
	grep -Eom1 '^\[.*\]$' "$rclone_config" | tr -d '[]' 2>/dev/null
}

rclone() {
	if [[ -z $rclone_path ]]; then
		rclone_path="$(which rclone)"
	fi

	"$rclone_path" "$@" --config "$rclone_config"
}

exit_handler() {
	if [[ ! -z $tmpdir ]] && [[ -e $tmpdir ]]; then
		rm -r "$tmpdir" &> /dev/null
	fi

	release_mutex
}

init_tmpdir() {
	if [[ -z $tmpdir ]]; then
		tmpdir="$(mktemp -d /tmp/systembackup.XXXXXXX)/"
		chown 700 "$tmpdir"
		chown "$USER": "$tmpdir"
	fi
}

install_base_dependencies() {
	local i
	local install_pkgs=()
	local deps=(unzip tar gzip wget gpg)
	local pkgs=(unzip tar gzip wget gnupg)

	for ((i = 0; i < ${#deps[@]}; i++)); do
		if ! which "${deps[$i]}" > /dev/null; then
			install_pkgs+=(${pkgs[$i]})
		fi
	done

	if [[ ${#install_pkgs[@]} -ne 0 ]]; then
		local distro_info="$(cat /etc/[A-Za-z]*[_-][rv]e[lr]*)"
		if [[ $distro_info =~ Ubuntu|Debian ]]; then
			apt-get install ${install_pkgs[@]}
		elif [[ $distro_info =~ Fedora|CentOS ]]; then
			yum install ${install_pkgs[@]}
		else
			echo 'Unsupported OS.'
		fi
	fi
}

install_rclone() {
	if [[ -z "$(which rclone)" ]]; then
		echo "Installing rclone..."

		init_tmpdir
		case "$(uname -m)" in
			i*86)
				local arch=386
				;;
			x86_64)
				local arch=amd64
				;;
			*)
				die 'Unknown architecture.'
				;;
		esac

		local url="$(wget -qO - https://github.com/ncw/rclone/releases | sed -nr \
			"s! *<a href=\"(/ncw/rclone/releases/download/v.*/rclone-v.*-linux-$arch.zip)\".*!https://github.com\1!gp" | head -n1)"
		if [[ -z $url ]]; then
			die 'Unable to find rclone binary URL from releases page.'
		else
			local archive_file="$tmpdir$(basename "$url")"
			local archive_dir="${archive_file%.zip}"
			wget "$url" -O "$archive_file"
			unzip "$archive_file" -d "$tmpdir"
			mkdir -p /usr/local/bin /usr/local/man/man1
			cp "$archive_dir/rclone" /usr/local/bin
			cp "$archive_dir/rclone.1" /usr/local/man/man1
		fi
	fi
}

interactive_config_setup() {
	local backup_path
	local command_name
	local backup_command
	local backup_paths=()
	local backup_password
	local encrypt_password
	local -A backup_commands

	HOSTNAME="$(hostname)"
	read -p "System name [default=$HOSTNAME]: " system_name
	if [[ ! $system_name =~ ^[a-zA-Z0-9_.-]+(\.[a-zA-Z0-9_.-]+)*$ ]]; then
		if [[ ! -z $system_name ]]; then
			echo 'Invalid system name, falling back to default.'
		fi
		system_name="$HOSTNAME"
	fi

	echo 'Enter the paths to back up. Wildcards are allowed, leave empty to finish.'
	while true; do
		read -p 'Path: ' backup_path
		if [[ -z $backup_path ]]; then
			break
		fi
		if [[ $backup_path =~ ^[^/]|(^|/)\.\.?($|/) ]]; then
			echo 'Relative/invalid path given.'
		else
			backup_paths+=("$(echo "$backup_path" | escape_str)")
		fi
	done

	echo 'Enter command outputs that will be backed up.'
	echo 'Enter a command name, followed by the command name itself; leave the name blank to exit.'
	while true; do
		read -p 'Name: ' command_name
		if [[ -z $command_name ]]; then
			break
		elif [[ ! $command_name =~ ^[a-zA-Z0-9_-]+$ ]]; then
			echo 'Invalid command name.'
			continue
		fi
		read -p 'Command: ' backup_command
		if [[ -z $backup_command ]]; then
			echo 'Empty command.'
			continue
		fi
		backup_commands["$command_name"]="$backup_command"
	done

	if [[ ${#backup_commands} -eq 0 ]] && [[ ${#backup_paths} -eq 0 ]]; then
		die 'Nothing to back up, exiting configuration.'
	fi

	while true; do
		read -sp 'Backup encryption password: '	encrypt_password
		echo
		if [[ $encrypt_password =~ ^(.{0,7}|password|(.)\2+)$ ]]; then
			echo 'This password is very weak.'
		else
			break
		fi
	done

	read -p 'Rotate after [default=5]: ' rotate
	if [[ ! $rotate =~ ^[1-9][0-9]* ]]; then
		if [[ ! -z $rotate ]]; then
			echo 'Invalid value, falling back to default.'
		fi
		rotate=5
	fi

	declare -p | grep -E '^declare -. (backup_(paths|commands)|encrypt_password|rotate|system_name)=' > "$backup_config"
}

run_setup() {
	acquire_mutex
	assert_root
	install_base_dependencies
	install_rclone

	mkdir -p "$datadir"

	local write_config='y'
	if [[ -e $backup_config ]]; then
		read -n1 -p 'An existing configuration exists. Overwrite? [y/N] ' write_config
		echo
		write_config="${write_config,}"
	fi

	if [[ $write_config == 'y' ]]; then
		interactive_config_setup
	fi

	local write_rclone_config='y'
	if [[ ! -z "$(get_remote_name)" ]]; then
		read -n1 -p 'An existing rclone configuration exists. Overwrite? [y/N] ' write_rclone_config
		echo
		write_rclone_config="${write_rclone_config,}"
	fi

	if [[ $write_rclone_config == 'y' ]]; then
		echo 'Create a new remote from the rclone configuration options below.'
		echo 'Only the first remote will be used.'
		echo
		rclone config
		if [[ -z "$(get_remote_name)" ]]; then
			echo 'You did not add a rclone remote. Until you do so, backups will not work.'
		fi
	fi

	chmod 700 "$datadir"
	chown -R "$USER" "$datadir"
}

run_backup() {
	acquire_mutex
	assert_root

	if [[ "$(stat -c '%a:%U' "$datadir")" != "700:$USER" ]]; then
		die "Incorrect permissions/ownership on $i, refusing to run backup process. (Possibly compromised credentials?)"
	fi

	if [[ -z "$(get_remote_name)" ]]; then
		die 'You did not add a rclone remote. Until you do so, backups will not work.'
	fi

	init_tmpdir
	local globstar_enabled
	shopt -s globstar

	echo 'Reading backup configuration...'
	source "$backup_config"
	local remote_name="$(get_remote_name)"
	local commands_dir="$tmpdir/command_results"
	local passphrase_file="$tmpdir/backup_password"
	local backup_archive="$tmpdir$system_name-$(date +%Y%m%d_%H%M%S).gpg"

	echo "$encrypt_password" > "$passphrase_file"
	mkdir "$commands_dir"

	echo 'Saving command results...'
	for name in "${!backup_commands[@]}"; do
		eval "${backup_commands[$name]}" > "$commands_dir/$name.txt"
	done

	echo 'Compressing and encrypting data...'
	cd "$tmpdir"
	eval "tar --ignore-failed-read -czf - command_results ${backup_paths[*]} | gpg -c --cipher-algo AES256 --compress-algo none --batch --passphrase-fd 1 --passphrase-file $passphrase_file -o $backup_archive"

	echo 'Initializing remote...'
	rclone mkdir "$remote_name:$system_name"
	while read file; do
	 	rclone delete "$remote_name:$system_name/$file"
	done < <(rclone lsf "$remote_name:$system_name" | sort -n | head -n -"$rotate")
	rclone cleanup "$remote_name:$system_name"

	echo 'Transferring backup...'
	rclone move "$backup_archive" "$remote_name:$system_name"
}

print_extract_help() {
	cat << EOM
Usage: $0 extract BACKUP_ARCHIVE [DECRYPTED_ARCHIVE]
Extracts a backup archive.

Where:
BACKUP_ARCHIVE    The backup archive file
DECRYPTED_ARCHIVE Name of the decrypted archive file (Optional)
EOM
}

run_extract() {
	if [[ $1 =~ ^(|-h|-?-?help)$ ]]; then
		print_extract_help
		exit 0
	fi

	local output
	if [[ ! -z $2 ]]; then
		output="$2"
	else
		output="${1%.*}.tar.gz"
		if [[ -e $output ]]; then
			die "Output already exists, please provide a name manually."
		fi
	fi

	gpg -d -o "$output" "$1" 
}

trap exit_handler EXIT

case "$1" in
	'' | '-h' | '-help' | '--help' | 'help')
		print_help
		exit 0
		;;
	'setup')
		set -e
		run_setup
		;;
	'backup')
		set -e
		run_backup
		;;
	'extract')
		set -e
		shift
		run_extract "$@"
		;;
	*)
		print_command_error "$1"
		;;
esac
