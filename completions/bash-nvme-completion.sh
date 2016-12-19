# bash tab completion for the nvme command line utility
# (unfortunately, bash won't let me add descriptions to cmds)
# Kelly Kaoudis kelly.n.kaoudis at intel.com, Aug. 2015

_cmds="list id-ctrl id-ns list-ns create-ns delete-ns \
	attach-ns detach-ns list-ctrl get-ns-id get-log \
	fw-log smart-log smart-log-add error-log \
	get_feature set-feature format fw-activate \
	fw-download admin-passthru io-passthru security-send \
	security-recv resv-acquire resv-register resv-release \
	resv-report dsm flush compare read write write-zeroes \
	write-uncor reset subsystem-reset show-regs discover \
	connect-all connect disconnect version help \
	intel lnvm memblaze"

nvme_list_opts () {
        local opts=""
	local compargs=""

	local nonopt_args=0
	for (( i=0; i < ${#words[@]}-1; i++ )); do
		if [[ ${words[i]} != -* ]]; then
			let nonopt_args+=1
		fi
	done

	if [ $nonopt_args -eq 2 ]; then
		opts="/dev/nvme* "
	fi

	opts+=" "

	case "$1" in
		"list")
		opts=""
		;;
		"id-ctrl")
		opts+=" --raw-binary -b --human-readable -H \
			--vendor-specific -v --output-format= -o"
		;;
		"id-ns")
		opts+=" --namespace-id= -n --raw-binary -b \
			--human-readable -H --vendor-specific -v \
			--force -f --output-format= -o"
			;;
		"list-ns")
		opts+=" --namespace-id= -n --al -a"
			;;
		"create-ns")
		opts+=" --nsze= -s --ncap= -c --flbas= -f \
			--dps= -d --nmic= -n"
			;;
		"delete-ns")
		opts+=" -namespace-id= -n"
			;;
		"attach-ns")
		opts+=" --namespace-id= -n --controllers= -c"
			;;
		"detach-ns")
		opts+=" --namespace-id= -n --controllers= -c"
			;;
		"list-ctrl")
		opts+=" --namespace-id= -n --cntid= -c"
			;;
		"get-ns-id")
			;;
		"get-log")
		opts+=" --log-id= -i --log-len= -l --namespace-id= -n \
			--raw-binary= -b"
			;;
		"fw-log")
		opts+=" --raw-binary -b --output-format= -o"
			;;
		"smart-log")
		opts+=" --namespace-id= -n --raw-binary -b \
			--output-format= -o"
			;;
		"smart-log-add")
		opts+=" --namespace-id= -n --raw-binary -b"
			;;
		"error-log")
		opts+=" --namespace-id= -n --raw-binary -b --log-entries= -e \
			--output-format= -o"
			;;
		"get-feature")
		opts+=" --namespace-id= -n --feature-id= -f --sel= -s \
			--data-len= -l --cdw11= --raw-binary -b \
			--human-readable -H"
			;;
		"set-feature")
		opts+=" --namespace-id= -n --feature-id= -f --value= -v \
			--data-len= -l -data= -d --value= --save -s"
			;;
		"format")
		opts+=" --namespace-id= -n --timeout= -t --lbaf= -l \
			--ses= -s --pil= -p -pi= -i --ms= -m --reset -r"
			;;
		"fw-activate")
		opts+=" --action= -a --slot= -s"
			;;
		"fw-download")
		opts+=" --fw= -f --xfer= -x --offset= -o"
			;;
		"admin-passthru")
		opts+=" --opcode= -o --flags= -f --prefil= -p --rsvd= -R \
			--namespace-id= -n --data-len= -l --metadata-len= -m \
			--timeout= -t --cdw2= -2 --cdw3= -3 --cdw10= -4 \
			--cdw11= -5 --cdw12= -6 --cdw13= -7 --cdw14= -8 \
			--cdw15= -9 --input-file= -i --raw-binary= -b \
			--show-command -s --dry-run -d --read -r --write -w"
			;;
		"io-passthru")
		opts+=" --opcode= -o --flags= -f --prefill= -p --rsvd= -R \
			--namespace-id= -n --data-len= -l --metadata-len= -m \
			--timeout= -t --cdw2= -2 --cdw3= -3 --cdw10= -4 \
			--cdw11= -5 --cdw12= -6 --cdw13= -7 --cdw14= -8 \
			--cdw15= -9 --input-file= -i --raw-binary= -b \
			--show-command -s --dry-run -d --read -r --write -w"
			;;
		"security-send")
		opts+=" --namespace-id= -n --file= -f --nssf= -N --secp= -p \
			--spsp= -s --tl= -t"
			;;
		"security-recv")
		opts+=" --namespace-id= -n --size= -x --secp= -p --spsp= -s \
			--al= -t --raw-binary -b"
			;;
		"resv-acquire")
		opts+=" --namespace-id= -n --crkey= -c --prkey= -p \
			--rtype= -t --racqa= -a --iekey= -i"
			;;
		"resv-register")
		opts+=" --namespace-id= -n --crkey= -c --nrkey= -k \
			--rrega= -r --cptpl= -p --iekey -i"
			;;
		"resv-release")
		opts+=" --namespace-id= -n --crkey -c --rtype= -t \
			--rrela= -a --iekey -i"
			;;
		"resv-report")
		opts+=" --namespace-id= -n --numd= -d --raw-binary= -b \
			--output-format= -o"
			;;
		"dsm")
		opts+=" --namespace-id= -n --ctx-attrs= -a --blocks= -b\
			-slbs= -s --ad -d --idw -w --idr -r --cdw11= -c"
			;;
		"flush")
		opts+=" --namespace-id= -n"
			;;
		"compare")
		opts+=" --start-block= -s --block-count= -c --data-size= -z \
			--metadata-size= -y --ref-tag= -r --data= -d \
			--metadata= -M --prinfo= -p --app-tag-mask= -m \
			--app-tag= -a --limited-retry -l \
			--force-unit-access -f --show-command -v \
			--dry-run -w --latency -t"
			;;
		"read")
		opts+=" --start-block= -s --block-count= -c --data-size= -z \
			--metadata-size= -y --ref-tag= -r --data= -d \
			--metadata= -M --prinfo= -p --app-tag-mask= -m \
			--app-tag= -a --limited-retry -l \
			--force-unit-access -f --show-command -v \
			--dry-run -w --latency -t"
			;;
		"write")
		opts+=" --start-block= -s --block-count= -c --data-size= -z \
			--metadata-size= -y --ref-tag= -r --data= -d \
			--metadata= -M --prinfo= -p --app-tag-mask= -m \
			--app-tag= -a --limited-retry -l \
			--force-unit-access -f --show-command -v \
			--dry-run -w --latency -t"
			;;
		"write-zeros")
		opts+=" --namespace-id= -n --start-block= -s \
			--block-count= -c --limited-retry -l \
			--force-unit-access -f --prinfo= -p --ref-tag= -r \
			--app-tag-mask= -m --app-tag= -a"
			;;
		"write-uncor")
		opts+=" --namespace-id= -n --start-block= -s \
			--block-count= -c"
			;;
		"reset")
		opts+=""
			;;
		"subsystem-reset")
		opts+=""
			;;
		"show-regs")
		opts+=" --human-readable -H"
			;;
		"discover")
		opts+=" --transport= -t -traddr= -a -trsvcid= -s \
			--hostnqn= -q --raw= -r"
			;;
		"connect-all")
		opts+=" --transport= -t --traddr= -a --trsvcid= -s
			--hostnqn= -q --raw= -r"
			;;
		"connect")
		opts+=" --transport= -t --nqn= -n --traddr= -a --trsvcid -s \
			--hostnqn= -q --nr-io-queues= -i --keep-alive-tmo -k \
			--reconnect-delay -r"
			;;
		"disconnect")
		opts+=" --nqn -n --device -d"
			;;
		"version")
		opts+=""
			;;
		"help")
		opts=$_cmds
			;;
	esac

        opts+=" -h --help"

	COMPREPLY+=( $( compgen $compargs -W "$opts" -- $cur ) )

	return 0
}

_nvme_subcmds () {
        local cur prev words cword
	_init_completion || return

	if [[ ${#words[*]} -lt 3 ]]; then
		COMPREPLY+=( $(compgen -W "$_cmds" -- $cur ) )
	else
		nvme_list_opts ${words[1]} $prev
	fi

	return 0
}

complete -o default -F _nvme_subcmds nvme
