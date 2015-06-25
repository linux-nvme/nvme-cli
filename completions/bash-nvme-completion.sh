#!/usr/bin/env bash

# bash tab completion for the nvme command line utility
# (unfortunately, bash won't let me add descriptions to cmds)
# Kelly Kaoudis kelly.n.kaoudis at intel.com, June 2015

_cmds="admin-passthru attach-ns compare create-ns delete-ns detach-ns error-log flush format fw-activate fw-download fw-log get-feature get-log get-ns-id help id-ctrl id-ns io-passthru list-ctrl list-ns read resv-acquire resv-register resv-release resv-report security-resv security-send set-feature show-regs smart-log write"

_nvme_list_opts () {
	local opts="/dev/nvme*"

	case "$1" in
		"admin-passthru")
		opts+=" --opcode= -o --flags= -f --rsvd= -R --namespace-id= -n --data-len= -l --metadata-len= -m --timeout= -t --cdw2= -2 --cdw3= -3 --cdw10= -4 --cdw11= -5 --cdw12= -6 --cdw13= -7 --cdw14= -8 --cdw15= -9 --input-file= -i --raw-binary= -b --show-command -s --dry-run -d --read -r --write -w"
			;;
		"attach-ns")
		opts+=" --namespace-id= -n --controllers= -c"
			;;
		"compare")
		opts+=" --start-block= -s --block-count= -c --metadata-size= -y --data-size= -z --data= -d --prinfo= -p --app-tag-mask= -m --app-tag= -a --limited-retry -l --force-unit-access -f"
			;;
		"create-ns")
		opts+=" --nsze= -s --ncap= -c --flbas= -f --dps= -d --nmic= -n"
			;;
		"delete-ns")
		opts+=" -namespace-id= -n"
			;;
		"detach-ns")
		opts+=" --namespace-id= -n --controllers= -c"
			;;
		"error-log")
		opts+=" --namespace-id= -n --raw-binary -b --log-entries= -e"
			;;
		"flush")
		opts+=" --namespace-id= -n"
			;;
		"format")
		opts+=" --namespace-id= -n --lbaf= -l --ses= -s --pil= -p --pi= -i --ms= -m"
			;;
		"fw-activate")
		opts+=" --action= -a --slot= -s"
			;;
		"fw-download")
		opts+=" --fw= -f --xfer= -x --offset= -o"
			;;
		"fw-log")
		opts+=" --raw-binary -b"
			;;
		"get-feature")
		opts+=" --namespace-id= -n --feature-id= -f --sel= -s --data-len= -l --cdw11= --raw-binary -b"
			;;
		"get-log")
		opts+=" --log-id= -i --log-len= -l --namespace-id= -n --raw-binary= -b"
			;;
		"get-ns-id")
			;;
		"help")
		opts=$_cmds
			;;
		"id-ctrl")
		opts+=" --raw-binary -b --human-readable -H --vendor-specific -v"
			;;
		"id-ns")
		opts+=" --namespace-id= -n --raw-binary -b --human-readable -H --vendor-specific -v"
			;;
		"list-ctrl")
		opts+=" --namespace-id= -n --cntid= -c"
			;;
		"list-ns")
		opts+=" --namespace-id= -n"
			;;
		"read")
		opts+=" --start-block= -s --block-count= -c --data-size= -z --metadata-size= -y --ref-tag= -r --data= -d --prinfo= -p --app-tag-mask= -m --app-tag= -a --limited-retry -l --latency -t --force-unit-access -f"
			;;
		"resv-acquire")
		opts+=" --namespace-id= -n --prkey= -p --rtype= -t --racqa= -a --iekey= -i"
			;;
		"resv-register")
		opts+=" --namespace-id= -n --crkey= -c --nrkey= -k --cptpl= -p --rrega= -a --iekey -i"
			;;
		"resv-release")
		opts+=" --namespace-id= -n --rtype= -t --rrela= -a --iekey -i"
			;;
		"resv-report")
		opts+=" --namespace-id= -n --numd= -d --raw-binary= -b"
			;;
		"security-recv")
		opts+=" --secp= -p --spsp= -s --size= -x --al= -a --raw-binary -b"
			;;
		"security-send")
		opts+=" --file= -f --secp= -p --spsp= -s --tl= -t"
			;;
		"set-feature")
		opts+=" --namespace-id= -n --feature-id= -f --data-len= -l --data= -d --value="
			;;
		"show-regs")
			;;
		"smart-log")
		opts+=" --namespace-id= -n --raw-binary -b"
			;;
		"write")
		opts+=" --start-block= -s --block-count= -c --data-size= -z --metadata-size= -y --ref-tag= -r --data= -d --prinfo= -p --app-tag-mask= -m --app-tag= -a --limited-retry -l --latency -t --force-unit-access -f"
			;;
	esac

	COMPREPLY+=( $( compgen -W "$opts" -- $cur ) )
	return 0
}

_nvme_subcmds () {
	local prev cur

	prev=${COMP_WORDS[COMP_CWORD - 1]}

	if [[ "$prev" != "nvme" ]]; then
		if [[ "$_cmds" =~ "$prev" ]]; then
			_nvme_list_opts $prev
		else
			_nvme_list_opts ${COMP_WORDS[1]}
		fi
	else
		COMPREPLY+=( $( compgen -W "$_cmds" -- $cur ) )
	fi

	return 0
}

complete -F _nvme_subcmds nvme
