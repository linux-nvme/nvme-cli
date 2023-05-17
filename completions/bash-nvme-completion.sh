# SPDX-License-Identifier: GPL-2.0-or-later
#
# bash tab completion for the nvme command line utility
# (unfortunately, bash won't let me add descriptions to cmds)
# Kelly Kaoudis kelly.n.kaoudis at intel.com, Aug. 2015

nvme_list_opts () {
	local opts=""
	local compargs=""
	local vals=""
	local opt=""
	local val=""

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
	vals+=" "

	if [[ $cur != -* ]] && [[ $cur != "" ]] && [[ $prev == "=" ]] && [[ ${words[$cword-2]} == --* ]]; then
		opt+="${words[$cword-2]}"
		val+="$cur"
	elif [[ $cur == "" ]] && [[ $prev != "=" ]] || [[ $cur == "=" ]] && [[ $prev == --* ]]; then
		opt+="$prev"
	elif [[ $cur != "=" ]] && [[ $prev != --* ]] && [[ $prev != "=" ]]; then
		opt+="$prev"
		val+="$cur"
	else
		opt+="$cur"
	fi

	# Listed here in the same order as in nvme-builtin.h
	case "$1" in
		"list")
		opts+=$NO_OPTS
			;;
		"list-subsys")
		opts=+=" --output-format= -o --verbose -v"
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
		"id-ns-granularity")
		opts+=" --output-format= -o"
			;;
		"id-ns-lba-format")
		opts+=" --lba-format-index= -i --uuid-index= -U \
			--verbose -v --output-format= -o"
			;;
		"list-ns")
		opts+=" --namespace-id= -n --al -a --csi= -y \
			--outputformat= -o"
			;;
		"list-ctrl")
		opts+=" --namespace-id= -n --cntid= -c \
			--output-format= -o"
			;;
		"cmdset-ind-id-ns")
		opts+=" --namespace-id= -n --raw-binary -b \
			--human-readable -H --output-format= -o"
			;;
		"nvm-id-ctrl")
		opts+=" --output-format= -o"
			;;
		"nvm-id-ns")
		opts+=" --namespace-id= -n --uuid-index= -U\
			--verbose -v --output-format= -o"
			;;
		"nvm-id-ns-lba-format")
		opts+=" --lba-format-index= -i --uuid-index= -U \
			--verbose -v --output-format= -o"
			;;
		"primary-ctrl-caps")
		opts+=" --output-format= -o --human-readable -H"
			;;
		"list-secondary")
		opts+=" --cntid= -c --namespace-id= n --num-entries -e \
			--output-format= -o"
			;;
		"ns-descs")
		opts+=" --namespace-id= -n --output-format -o --raw-binary -b"
			;;
		"id-nvmset")
		opts+=" --nvmeset-id= -i --output-format= -o"
			;;
		"id-uuid")
		opts+=" --output-format= -o --raw-binary -b --human-readable -H"
			;;
		"list-endgrp")
		opts+=" --endgrp-id= -i --output-format= -o"
			;;
		"id-iocs")
		opts+=" --controller-id= -c"
			;;
		"id-domain")
		opts+=" --domain-id= -c --output-format= -o"
			;;
		"create-ns")
		opts+=" --nsze= -s --ncap= -c --flbas= -f \
			--dps= -d --nmic= -m --anagrp-id= -a --nvmset-id= -i \
			--block-size= -b --timeout= -t --csi= -y --lbstm= -l \
			--nphndls= -n --nsze-si= -S --ncap-si= -C --azr -z --rar= -r \
			--ror= -o --rnumzrwa= -u --phndls= -p"
			;;
		"delete-ns")
		opts+=" -namespace-id= -n --timeout= -t"
			;;
		"attach-ns")
		opts+=" --namespace-id= -n --controllers= -c"
			;;
		"detach-ns")
		opts+=" --namespace-id= -n --controllers= -c"
			;;
		"get-ns-id")
		opts+=$NO_OPTS
			;;
		"get-log")
		opts+=" --log-id= -i --log-len= -l --namespace-id= -n \
			--aen= -a --lpo= -o --lsp= -s --lsi= -S \
			--rae -r --uuid-index= -U --csi= -y --ot -O \
			--raw-binary -b"
			;;
		"supported-log-pages")
		opts+=" --output-format= -o --human-readable -H"
			;;
		"telemetry-log")
		opts+=" --output-file= -o --host-generate= -g \
			--controller-init -c --data-area= -d"
			;;
		"fw-log")
		opts+=" --raw-binary -b --output-format= -o"
			;;
		"changed-ns-list-log")
		opts+=" --output-format= -o --raw-binary -b"
			;;
		"smart-log")
		opts+=" --namespace-id= -n --raw-binary -b \
			--output-format= -o"
			;;
		"ana-log")
		opts+=" --output-format -o"
			;;
		"fid-support-effects-log")
		opts+=" --output-format -o"
			;;
		"error-log")
		opts+=" --raw-binary -b --log-entries= -e \
			--output-format= -o"
			;;
		"effects-log")
		opts+=" --output-format= -o --human-readable -H \
			--raw-binary -b"
			;;
		"endurance-log")
		opts+=" --output-format= -o --group-id -g"
			;;
		"predictable-lat-log")
		opts+=" --nvmset-id= -i --raw-binary -b \
			--output-format= -o"
			;;
		"pred-lat-event-agg-log")
		opts+=" --log-entries= -e  --rae -r \
			--raw-binary -b --output-format= -o"
			;;
		"persistent-event-log")
		opts+=" --action= -a --log-len= -l \
			--raw-binary -b --output-format= -o"
			;;
		"endurance-event-agg-log")
		opts+=" --log-entries= -e  --rae -r \
			--raw-binary -b --output-format= -o"
			;;
		"lba-status-log")
		opts+=" --rae -r --output-format= -o"
			;;
		"resv-notif-log")
		opts+=" --output-format= -o"
			;;
		"boot-part-log")
		opts+=" --lsp -s --output-file= -f \
			--output-format= -o"
			;;
		"media-unit-stat-log")
		opts+=" --dom-id= -d --output-format= -o \
			--raw-binary -b"
			;;
		"supported-cap-config-log")
		opts+=" --dom-id= -d --output-format= -o \
				--raw-binary -b"
			;;
		"get-feature")
		opts+=" --namespace-id= -n --feature-id= -f --sel= -s \
			--data-len= -l --cdw11= --c -uuid-index= -U --raw-binary -b \
			--human-readable -H"
			;;
		"device-self-test")
		opts+=" --namespace-id= -n --self-test-code= -s"
			;;
		"self-test-log")
		opts+=" --dst-entries= -e --output-format= -o \
			--verbose -v"
			;;
		"set-feature")
		opts+=" --namespace-id= -n --feature-id= -f --value= -v \
			--data-len= -l -data= -d --value= -v --save -s --uuid-index= -U \
			--cdw12= -c"
			;;
		"set-property")
		opts+=" --offset= -o --value= -v"
			;;
		"get-property")
		opts=+" --offset= -o --human-readable -H"
			;;
		"format")
		opts+=" --namespace-id= -n --timeout= -t --lbaf= -l \
			--ses= -s --pil= -p -pi= -i --ms= -m --reset -r"
			;;
		"fw-commit")
		opts+=" --slot= -s --action= -a --bpid= -b"
			;;
		"fw-download")
		opts+=" --fw= -f --xfer= -x --offset= -o"
			;;
		"capacity-mgmt")
		opts+=" --operation= -f --element-id= -i --cap-lower= -l \
				--cap-upper= -u"
			;;
		"lockdown")
		opts+=" --ofi= -O --ifc= -F --prhbt= -P \
			-scp= -S --uuid -U"
			;;
		"admin-passthru")
		opts+=" --opcode= -o --flags= -f --prefil= -p --rsvd= -R \
			--namespace-id= -n --data-len= -l --metadata-len= -m \
			--timeout= -t --cdw2= -2 --cdw3= -3 --cdw10= -4 \
			--cdw11= -5 --cdw12= -6 --cdw13= -7 --cdw14= -8 \
			--cdw15= -9 --input-file= -i --raw-binary -b \
			--show-command -s --dry-run -d --read -r --write -w \
			--latency -T"
			;;
		"io-passthru")
		opts+=" --opcode= -o --flags= -f --prefill= -p --rsvd= -R \
			--namespace-id= -n --data-len= -l --metadata-len= -m \
			--timeout= -t --cdw2= -2 --cdw3= -3 --cdw10= -4 \
			--cdw11= -5 --cdw12= -6 --cdw13= -7 --cdw14= -8 \
			--cdw15= -9 --input-file= -i --raw-binary -b \
			--show-command -s --dry-run -d --read -r --write -w \
			--latency -T"
			;;
		"security-send")
		opts+=" --namespace-id= -n --file= -f --nssf= -N --secp= -p \
			--spsp= -s --tl= -t"
			;;
		"security-recv")
		opts+=" --namespace-id= -n --size= -x --secp= -p --spsp= -s \
			--al= -t --raw-binary -b"
			;;
		"get-lba-status")
		opts+=" --namespace-id= -n --start-lba= -s --max-dw= -m \
			--action= -a --range-len= -l --timeout= -t \
			--output-format= -o"
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
		opts+=" --namespace-id= -n --numd= -d --eds -e \
			--raw-binary= -b --output-format= -o"
			;;
		"dsm")
		opts+=" --namespace-id= -n --ctx-attrs= -a --blocks= -b\
			--slbs= -s --ad -d --idw -w --idr -r --cdw11= -c"
			;;
		"copy")
		opts+=" --namespace-id= -n --sdlba= -d --blocks= -b --slbs= -s \
			--limited-retry -l --force-unit-access -f \
			--prinfow= -p --prinfor= -P \
			--ref-tag= -r --expected-ref-tag= -R \
			--app-tag= -a --expected-app-tag= -A \
			--app-tag-mask= -m --expected-app-tag-mask= -M \
			--dir-type= -T --dir-spec= -S --format= -F"
			;;
		"flush")
		opts+=" --namespace-id= -n"
			;;
		"compare")
		opts+=" --start-block= -s --block-count= -c --data-size= -z \
			--metadata-size= -y --ref-tag= -r --data= -d \
			--metadata= -M --prinfo= -p --app-tag-mask= -m \
			--app-tag= -a --limited-retry -l \
			--force-unit-access -f --storage-tag-check -C \
			--dir-type= -T --dir-spec= -S --dsm= -D --show-command -v \
			--dry-run -w --latency -t"
			;;
		"read")
		opts+=" --start-block= -s --block-count= -c --data-size= -z \
			--metadata-size= -y --ref-tag= -r --data= -d \
			--metadata= -M --prinfo= -p --app-tag-mask= -m \
			--app-tag= -a --limited-retry -l \
			--force-unit-access -f --storage-tag-check -C \
			--dir-type= -T --dir-spec= -S --dsm= -D --show-command -v \
			--dry-run -w --latency -t"
			;;
		"write")
		opts+=" --start-block= -s --block-count= -c --data-size= -z \
			--metadata-size= -y --ref-tag= -r --data= -d \
			--metadata= -M --prinfo= -p --app-tag-mask= -m \
			--app-tag= -a --limited-retry -l \
			--force-unit-access -f --storage-tag-check -C \
			--dir-type= -T --dir-spec= -S --dsm= -D --show-command -v \
			--dry-run -w --latency -t"
			;;
		"write-zeroes")
		opts+=" --namespace-id= -n --start-block= -s \
			--block-count= -c --deac -d --limited-retry -l \
			--force-unit-access -f --prinfo= -p --ref-tag= -r \
			--app-tag-mask= -m --app-tag= -a \
			--storage-tag= -S --storage-tag-check -C \
			--dir-type= -T --dir-spec= -S"
			;;
		"write-uncor")
		opts+=" --namespace-id= -n --start-block= -s \
			--block-count= -c --dir-type= -T --dir-spec= -S"
			;;
		"verify")
		opts+=" --namespace-id= -n --start-block= -s \
			--block-count= -c --limited-retry -l \
			--force-unit-access -f --prinfo= -p --ref-tag= -r \
			--app-tag= -a --app-tag-mask= -m \
			--storage-tag= -S --storage-tag-check -C"
			;;
		"sanitize")
		opts+=" --no-dealloc -d --oipbp -i --owpass= -n \
			--ause -u --sanact= -a --ovrpat= -p"
		case $opt in
			--sanact|-a)
			vals+=" exit-failure start-block-erase start-overwrite start-crypto-erase"
				;;
		esac
			;;
		"sanitize-log")
		opts+=" --rae -r --output-format= -o --human-readable -H \
			--raw-binary -b"
			;;
		"reset")
		opts+=$NO_OPTS
			;;
		"subsystem-reset")
		opts+=$NO_OPTS
			;;
		"ns-rescan")
		opts+=$NO_OPTS
			;;
		"show-regs")
		opts+=" --output-format= -o --human-readable -H"
			;;
		"discover")
		opts+=" --transport= -t -traddr= -a -trsvcid= -s \
			--host-traddr= -w --host-iface= -f \
			--hostnqn= -q --hostid -I --raw= -r \
			--raw= -r --device= -d --keep-alive-tmo= -k \
			--ctrl-loss-tmo= -l --fast-io-fail-tmo= -f \
			--tos= -T --hdr-digest= -g --data-digest -G \
			--nr-io-queues= -i --nr-write-queues= -W \
			--nr-poll-queues= -P --queue-size= -Q \
			--persistent -p --quiet -S \
			--output-format= -o"
			;;
		"connect-all")
		opts+=" --transport= -t -traddr= -a -trsvcid= -s \
			--host-traddr= -w --host-iface= -f \
			--hostnqn= -q --hostid -I --raw= -r \
			--raw= -r --device= -d --keep-alive-tmo= -k \
			--ctrl-loss-tmo= -l --fast-io-fail-tmo= -f \
			--tos= -T --hdr-digest= -g --data-digest -G \
			--nr-io-queues= -i --nr-write-queues= -W \
			--nr-poll-queues= -P --queue-size= -Q \
			--persistent -p --quiet -S \
			--output-format= -o"
			;;
		"connect")
		opts+=" --transport= -t --nqn= -n --traddr= -a --trsvcid -s \
			--hostnqn= -q --host-id= -I --nr-io-queues= -i \
			--nr-poll-queues= -P --queue-size= -Q \
			--keep-alive-tmo= -k --reconnect-delay= -r \
			--ctrl-loss-tmo= -l --fast-io-fail-tmo= -f \
			--tos= -T --duplicate-connect -D --disable-sqflow -d\
			--hdr-digest -g --data-digest -G --output-format= -o"
			;;
		"dim")
		opts+=" --task -t --nqn -n --device -d"
			;;
		"disconnect")
		opts+=" --nqn -n --device -d"
			;;
		"disconnect-all")
		opts+=$NO_OPTS
			;;
		"gen-hostnqn")
		opts+=$NO_OPTS
			;;
		"show-hostnqn")
		opts+=$NO_OPTS
			;;
		"dir-receive")
		opts+=" --namespace-id= -n --data-len= -l --raw-binary -b \
			--dir-type= -D --dir-spec= -S --dir-oper= -O \
			--req-resource= -r --human-readable -H"
			;;
		"dir-send")
		opts+=" --namespace-id= -n --data-len= -l --dir-type= -D \
			--target-dir= -T --dir-spec= -S --dir-oper= -O \
			--endir= -e --human-readable -H --raw-binary -b"
			;;
		"virt-mgmt")
		opts+=" --cntlid= -c --rt= -r --act= -a --nr= -n"
			;;
		"rpmb")
		opts+=" --cmd= -c --msgfile= -f --keyfile= -g \
			--key= -k --msg= -d --address= -o --blocks= -b \
			--target= -t"
			;;
		"show-topology")
		opts+=" --output-format= -o --verbose -v --ranking= -r"
			;;
		"version")
		opts+=$NO_OPTS
			;;
		"help")
		opts=$_cmds
			;;
	esac

	opts+=" -h --help -j --json"

	if [[ $vals == " " ]]; then
		COMPREPLY+=( $( compgen $compargs -W "$opts" -- $cur ) )
	else
		COMPREPLY+=( $( compgen $compargs -W "$vals" -- $val ) )
	fi

	return 0
}

plugin_intel_opts () {
    local opts=""
	local compargs=""

	local nonopt_args=0
	for (( i=0; i < ${#words[@]}-1; i++ )); do
		if [[ ${words[i]} != -* ]]; then
			let nonopt_args+=1
		fi
	done

	if [ $nonopt_args -eq 3 ]; then
		opts="/dev/nvme* "
	fi

	opts+=" "

	case "$1" in
		"id-ctrl")
		opts+=" --raw-binary -b --human-readable -H \
			--vendor-specific -v --output-format= -o"
			;;
		"internal-log")
		opts+=" --log= -l --region= -r --nlognum= -m \
			--namespace-id= -n --output-file= -o \
			--verbose-nlog -v"
			;;
		"lat-stats")
		opts+=" --write -w --raw-binary -b --json -j"
			;;
		"set-bucket-thresholds")
		opts+=" --write -w --bucket-thresholds= -t"
			;;
		"lat-stats-tracking")
		opts+=" --enable -e --disable -d"
			;;
		"market-name")
		opts+=" --raw-binary -b"
			;;
		"smart-log-add")
		opts+=" --namespace-id= -n --raw-binary -b \
			--json -j"
			;;
		"temp-stats")
		opts+=" --raw-binary -b"
			;;
		"help")
		opts+=$NO_OPTS
			;;
	esac

	COMPREPLY+=( $( compgen $compargs -W "$opts" -- $cur ) )

	return 0
}

plugin_amzn_opts () {
    local opts=""
	local compargs=""

	local nonopt_args=0
	for (( i=0; i < ${#words[@]}-1; i++ )); do
		if [[ ${words[i]} != -* ]]; then
			let nonopt_args+=1
		fi
	done

	if [ $nonopt_args -eq 3 ]; then
		opts="/dev/nvme* "
	fi

	opts+=" "

	case "$1" in
		"id-ctrl")
		opts+=" --raw-binary -b --human-readable -H \
			--vendor-specific -v --output-format= -o"
			;;
		"help")
		opts+=$NO_OPTS
			;;
	esac

	COMPREPLY+=( $( compgen $compargs -W "$opts" -- $cur ) )

	return 0
}

plugin_memblaze_opts () {
    local opts=""
	local compargs=""

	local nonopt_args=0
	for (( i=0; i < ${#words[@]}-1; i++ )); do
		if [[ ${words[i]} != -* ]]; then
			let nonopt_args+=1
		fi
	done

	if [ $nonopt_args -eq 3 ]; then
		opts="/dev/nvme* "
	fi

	opts+=" "

	case "$1" in
		"smart-log-add")
		opts+=" --namespace-id= -n --raw-binary -b"
			;;
		"get-pm-status")
		opts+=$NO_OPTS
			;;
		"set-pm-status")
		opts+=" --value= -v --save -s"
			;;
		"select-download")
		opts+=" --fw= -f --select= -s"
			;;
		"lat-stats")
		opts+=" --enable -e --disable -d"
			;;
		"lat-stats-print")
		opts+=" --write -w"
			;;
		"lat-log")
		opts+=" --param= -p"
			;;
		"lat-log-print")
		opts+=$NO_OPTS
			;;
		"clear-error-log")
		opts+=$NO_OPTS
			;;
		"help")
		opts+=$NO_OPTS
			;;
	esac

	COMPREPLY+=( $( compgen $compargs -W "$opts" -- $cur ) )

	return 0
}

plugin_wdc_opts () {
    local opts=""
	local compargs=""

	local nonopt_args=0
	for (( i=0; i < ${#words[@]}-1; i++ )); do
		if [[ ${words[i]} != -* ]]; then
			let nonopt_args+=1
		fi
	done

	if [ $nonopt_args -eq 3 ]; then
		opts="/dev/nvme* "
	fi

	opts+=" "

	case "$1" in
		"cap-diag")
		opts+=" --output-file= -o --transfer-size= -s"
			;;
		"drive-log")
		opts+=" --output-file= -o"
			;;
		"get-crash-dump")
		opts+=" --output-file= -o"
			;;
		"get-pfail-dump")
		opts+=" --output-file= -o"
			;;
		"id-ctrl")
		opts+=" --raw-binary -b --human-readable -H \
			--vendor-specific -v --output-format= -o"
			;;
		"purge")
		opts+=$NO_OPTS
			;;
		"purge-monitor")
		opts+=$NO_OPTS
			;;
		"vs-internal-log")
		opts+=" --output-file= -o --transfer-size= -s --data-area= -d \
			--file-size= -f --offset= -e --type= -t --verbose -v"
			;;
		"vs-nand-stats")
		opts+=" --output-format= -o"
			;;
		"vs-smart-add-log")
		opts+=" --interval= -i --output-format= -o --log-page-version= -l \
			--log-page-mask= -p"
			;;
		"clear-pcie-correctable-errors")
		opts+=$NO_OPTS
			;;
		"drive-essentials")
		opts+=" --dir-name= -d"
			;;
		"get-drive-status")
		opts+=$NO_OPTS
			;;
		"clear-assert-dump")
		opts+=$NO_OPTS
			;;
		"drive-resize")
		opts+=" --size= -s"
			;;
		"vs-fw-activate-history")
		opts+=" --output-format= -o"
			;;
		"clear-fw-activate-history")
		opts+=$NO_OPTS
			;;
		"enc-get-log")
		opts+=" --output-file= -o --transfer-size= -s --log-id= -l"
			;;
		"vs-telemetry-controller-option")
		opts+=" --disable -d --enable -e --status -s"
			;;
		"vs-error-reason-identifier")
		opts+=" --log-id= -i --file= -o"
			;;
		"log-page-directory")
		opts+=" --output-format= -o"
			;;
		"namespace-resize")
		opts+=" --namespace-id= -n --op-option= -o"
			;;
		"vs-drive-info")
		opts+=" --output-format= -o"
			;;
		"vs-temperature-stats")
		opts+=" --output-format= -o"
			;;
		"capabilities")
		opts+=$NO_OPTS
			;;
		"cloud-SSD-plugin-version")
		opts+=$NO_OPTS
			;;
		"vs-pcie-stats")
		opts+=" --output-format= -o"
			;;
		"help")
		opts+=$NO_OPTS
			;;
	esac

	COMPREPLY+=( $( compgen $compargs -W "$opts" -- $cur ) )

	return 0
}

plugin_huawei_opts () {
    local opts=""
	local compargs=""

	local nonopt_args=0
	for (( i=0; i < ${#words[@]}-1; i++ )); do
		if [[ ${words[i]} != -* ]]; then
			let nonopt_args+=1
		fi
	done

	if [ $nonopt_args -eq 3 ]; then
		opts="/dev/nvme* "
	fi

	opts+=" "

	case "$1" in
		"list")
		opts+=" --output-format= -o"
			;;
		"id-ctrl")
		opts+=" --raw-binary -b --human-readable -H \
			--vendor-specific -v --output-format= -o"
			;;
		"help")
		opts+=$NO_OPTS
			;;
	esac

	COMPREPLY+=( $( compgen $compargs -W "$opts" -- $cur ) )

	return 0
}

plugin_toshiba_opts () {
    local opts=""
	local compargs=""

	local nonopt_args=0
	for (( i=0; i < ${#words[@]}-1; i++ )); do
		if [[ ${words[i]} != -* ]]; then
			let nonopt_args+=1
		fi
	done

	if [ $nonopt_args -eq 3 ]; then
		opts="/dev/nvme* "
	fi

	opts+=" "

	case "$1" in
		"vs-smart-add-log")
		opts+=" --namespace-id= -n --output-file= -o --log= -l"
			;;
		"vs-internal-log")
		opts+=" --output-file= -o --prev-log -p"
			;;
		"clear-pcie-correctable-errors")
		opts+=$NO_OPTS
			;;
		"help")
		opts+=$NO_OPTS
			;;
	esac

	COMPREPLY+=( $( compgen $compargs -W "$opts" -- $cur ) )

	return 0
}

plugin_micron_opts () {
    local opts=""
	local compargs=""

	local nonopt_args=0
	for (( i=0; i < ${#words[@]}-1; i++ )); do
		if [[ ${words[i]} != -* ]]; then
			let nonopt_args+=1
		fi
	done

	if [ $nonopt_args -eq 3 ]; then
		opts="/dev/nvme* "
	fi

	opts+=" "

	case "$1" in
		"select-download")
		opts+=" --fw= -f --select= -s"
			;;
		"vs-temperature-stats")
		opts+=" --format= -f"
			;;
		"vs-pcie-stats")
		opts+=" --format= -f"
			;;
		"clear-pcie-correctable-errors")
		opts+=$NO_OPTS
			;;
		"vs-internal-log")
		opts+=" --type= -t --package= -p --data_area= -d"
			;;
		"vs-telemetry-controller-option")
		opts+=" --option= -o --select= -s"
			;;
		"vs-nand-stats")
		opts+=" --format= -f"
			;;
		"vs-drive-info")
		opts+=" --format= -f"
			;;
		"plugin-version")
		opts+=$NO_OPTS
			;;
		"cloud-SSD-plugin-version")
		opts+=$NO_OPTS
			;;
		"log-page-directory")
		opts+=$NO_OPTS
			;;
		"vs-fw-activate-history")
		opts+=" --format= -f"
			;;
		"vs-error-reason-identifier")
		opts+=" --format= -f"
			;;
		"vs-smart-add-log")
		opts+=" --format= -f"
			;;
		"clear-fw-activate-history")
		opts+=$NO_OPTS
			;;
		"vs-smbus-option")
		opts+=" --option= -o --value= -v --save= -s"
			;;
		"help")
		opts+=$NO_OPTS
			;;
	esac

	COMPREPLY+=( $( compgen $compargs -W "$opts" -- $cur ) )

	return 0
}

plugin_seagate_opts () {
    local opts=""
	local compargs=""

	local nonopt_args=0
	for (( i=0; i < ${#words[@]}-1; i++ )); do
		if [[ ${words[i]} != -* ]]; then
			let nonopt_args+=1
		fi
	done

	if [ $nonopt_args -eq 3 ]; then
		opts="/dev/nvme* "
	fi

	opts+=" "

	case "$1" in
		"vs-temperature-stats")
		opts+=" --output-format= -o"
			;;
		"vs-log-page-sup")
		opts+=" --output-format= -o"
			;;
		"vs-smart-add-log")
		opts+=" --output-format= -o"
			;;
		"vs-pcie-stats")
		opts+=" --output-format= -o"
			;;
		"clear-pcie-correctable-errors")
		opts+=" --save -s"
			;;
		"get-host-tele")
		opts+=" --namespace-id= -n --log-specific= -i --raw-binary -b"
			;;
		"get-ctrl-tele")
		opts+=" --namespace-id= -n --raw-binary -b"
			;;
		"vs-internal-log")
		opts+=" --namespace-id= -n --dump-file= -f"
			;;
		"plugin-version")
		opts+=$NO_OPTS
			;;
		"help")
		opts+=""
			;;
	esac

	COMPREPLY+=( $( compgen $compargs -W "$opts" -- $cur ) )

	return 0
}

plugin_virtium_opts () {
    local opts=""
	local compargs=""

	local nonopt_args=0
	for (( i=0; i < ${#words[@]}-1; i++ )); do
		if [[ ${words[i]} != -* ]]; then
			let nonopt_args+=1
		fi
	done

	if [ $nonopt_args -eq 3 ]; then
		opts="/dev/nvme* "
	fi

	opts+=" "

	case "$1" in
		"save-smart-to-vtview-log")
		opts+=" --run-time= -r --freq= -f --output-file= -o --test-name= -n"
			;;
		"show-identify")
		opts+=$NO_OPTS
			;;
		"help")
		opts+=$NO_OPTS
			;;
	esac

	COMPREPLY+=( $( compgen $compargs -W "$opts" -- $cur ) )

	return 0
}

plugin_shannon_opts () {
    local opts=""
	local compargs=""

	local nonopt_args=0
	for (( i=0; i < ${#words[@]}-1; i++ )); do
		if [[ ${words[i]} != -* ]]; then
			let nonopt_args+=1
		fi
	done

	if [ $nonopt_args -eq 3 ]; then
		opts="/dev/nvme* "
	fi

	opts+=" "

	case "$1" in
		"smart-log-add")
		opts+=" --namespace-id= -n --raw-binary -b"
			;;
		"get-feature-add")
		opts+=" --namespace-id= -n --feature-id -f --sel= -s \
			--data-len= -l --raw-binary -b --cdw11= -c --human-readable -H"
			;;
		"set-feature-add")
		opts+=" --namespace-id= -n --feature-id= -f --value= -v \
			--data-len= -l --data= -d --save -s"
			;;
		"id-ctrl")
		opts+=" --raw-binary -b --human-readable -H \
			--vendor-specific -v --output-format= -o"
			;;
		"help")
		opts+=$NO_OPTS
			;;
	esac

	COMPREPLY+=( $( compgen $compargs -W "$opts" -- $cur ) )

	return 0
}

plugin_dera_opts () {
    local opts=""
	local compargs=""

	local nonopt_args=0
	for (( i=0; i < ${#words[@]}-1; i++ )); do
		if [[ ${words[i]} != -* ]]; then
			let nonopt_args+=1
		fi
	done

	if [ $nonopt_args -eq 3 ]; then
		opts="/dev/nvme* "
	fi

	opts+=" "

	case "$1" in
		"smart-log-add")
		opts+=$NO_OPTS
			;;
		"help")
		opts+=$NO_OPTS
			;;
	esac

	COMPREPLY+=( $( compgen $compargs -W "$opts" -- $cur ) )

	return 0
}

plugin_sfx_opts () {
    local opts=""
	local compargs=""

	local nonopt_args=0
	for (( i=0; i < ${#words[@]}-1; i++ )); do
		if [[ ${words[i]} != -* ]]; then
			let nonopt_args+=1
		fi
	done

	if [ $nonopt_args -eq 3 ]; then
		opts="/dev/nvme* "
	fi

	opts+=" "

	case "$1" in
		"smart-log-add")
		opts+=" --namespace-id= -n --raw-binary -b --json -j"
			;;
		"lat-stats")
		opts+=" --write -w --raw-binary -b"
			;;
		"get-bad-block")
		opts+=$NO_OPTS
			;;
		"query-cap")
		opts+=" --raw-binary --json"
			;;
		"change-cap")
		opts+=" --cap= -c --cap-byte= -z --force -f --raw-binary -b --json -j"
			;;
		"set-feature")
		opts+=" --namespace-id= -n --feature-id= -f --value= -v --force -s"
			;;
		"get-feature")
		opts+=" --namespace-id= -n --feature-id -f"
			;;
		"help")
		opts+=$NO_OPTS
			;;
	esac

	COMPREPLY+=( $( compgen $compargs -W "$opts" -- $cur ) )

	return 0
}

plugin_transcend_opts () {
    local opts=""
	local compargs=""

	local nonopt_args=0
	for (( i=0; i < ${#words[@]}-1; i++ )); do
		if [[ ${words[i]} != -* ]]; then
			let nonopt_args+=1
		fi
	done

	if [ $nonopt_args -eq 3 ]; then
		opts="/dev/nvme* "
	fi

	opts+=" "

	case "$1" in
		"healthvalue")
		opts+=$NO_OPTS
			;;
		"badblock")
		opts+=$NO_OPTS
			;;
		"help")
		opts+=$NO_OPTS
			;;
	esac

	COMPREPLY+=( $( compgen $compargs -W "$opts" -- $cur ) )

	return 0
}

plugin_zns_opts () {
    local opts=""
	local compargs=""

	local nonopt_args=0
	for (( i=0; i < ${#words[@]}-1; i++ )); do
		if [[ ${words[i]} != -* ]]; then
			let nonopt_args+=1
		fi
	done

	if [ $nonopt_args -eq 3 ]; then
		opts="/dev/nvme* "
	fi

	opts+=" "

	case "$1" in
		"id-ctrl")
		opts+=" --raw-binary -b --human-readable -H \
			--vendor-specific -v --output-format= -o"
			;;
		"id-ns")
		opts+=" --namespace-id= -n --vendor-specific -v \
			--output-format= -o --human-readable -H"
			;;
		"zone-mgmt-recv")
		opts+=" --output-format= -o --namespace-id= -n \
			--start-lba= -s --zra= -z --zrasf= -S --partial -p \
			--data-len= -l"
			;;
		"zone-mgmt-send")
		opts+=" --namespace-id= -n --start-lba= -s --zsaso -o \
			--select-all -a --zsa= -z --data-len= -l \
			--data= -d --timeout= -t"
			;;
		"report-zones")
		opts+=" --namespace-id= -n --start-lba= -s \
			--descs= -d --state= -S --output-format= -o \
			--human-readable -H --extended -e --partial -p"
			;;
		"close-zone")
		opts+=" --namespace-id= -n --start-lba= -s \
			--select-all -a --timeout= -t"
			;;
		"finish-zone")
		opts+=" --namespace-id= -n --start-lba= -s \
			--select-all -a --timeout= -t"
			;;
		"open-zone")
		opts+=" --namespace-id= -n --start-lba= -s \
			--select-all -a --timeout= -t --zrwa -r"
			;;
		"reset-zone")
		opts+=" --namespace-id= -n --start-lba= -s \
			--select-all -a --timeout= -t"
			;;
		"offline-zone")
		opts+=" --namespace-id= -n --start-lba= -s \
			--select-all -a --timeout= -t"
			;;
		"set-zone-desc")
		opts+=" --namespace-id= -n --start-lba= -s \
			--data= -d --timeout= -t  --zrwa -r"
			;;
		"flush-zone")
		opts+=" --namespace-id= -n --last-lba= -l --timeout= -t"
			;;
		"zone-append")
		opts+=" --namespace-id= -n --zslba= -s --data-size= -z \
			--metadata-size= -y --data= -d --metadata= -M \
			--limited-retry -l --force-unit-access -f --ref-tag= -r
			--app-tag-mask= -m --app-tag= -a --prinfo= -p \
			--piremap -P --latency -t"
			;;
		"changed-zone-list")
		opts+=" --namespace-id= -n --output-format= -o --rae -r"
			;;
		"help")
		opts+=$NO_OPTS
			;;
	esac

	COMPREPLY+=( $( compgen $compargs -W "$opts" -- $cur ) )

	return 0
}

plugin_nvidia_opts () {
    local opts=""
	local compargs=""

	local nonopt_args=0
	for (( i=0; i < ${#words[@]}-1; i++ )); do
		if [[ ${words[i]} != -* ]]; then
			let nonopt_args+=1
		fi
	done

	if [ $nonopt_args -eq 3 ]; then
		opts="/dev/nvme* "
	fi

	opts+=" "

	case "$1" in
		"id-ctrl")
		opts+=" --raw-binary -b --human-readable -H \
			--vendor-specific -v --output-format= -o"
			;;
		"help")
		opts+=$NO_OPTS
			;;
	esac

	COMPREPLY+=( $( compgen $compargs -W "$opts" -- $cur ) )

	return 0
}

plugin_ymtc_opts () {
    local opts=""
	local compargs=""

	local nonopt_args=0
	for (( i=0; i < ${#words[@]}-1; i++ )); do
		if [[ ${words[i]} != -* ]]; then
			let nonopt_args+=1
		fi
	done

	if [ $nonopt_args -eq 3 ]; then
		opts="/dev/nvme* "
	fi

	opts+=" "

	case "$1" in
		"smart-log-add")
		opts+=" --namespace-id= -n --raw-binary -b"
			;;
		"help")
		opts+=$NO_OPTS
			;;
	esac

	COMPREPLY+=( $( compgen $compargs -W "$opts" -- $cur ) )

	return 0
}

plugin_inspur_opts () {
    local opts=""
	local compargs=""

	local nonopt_args=0
	for (( i=0; i < ${#words[@]}-1; i++ )); do
		if [[ ${words[i]} != -* ]]; then
			let nonopt_args+=1
		fi
	done

	if [ $nonopt_args -eq 3 ]; then
		opts="/dev/nvme* "
	fi

	opts+=" "

	case "$1" in
		"nvme-vendor-log")
		opts+=$NO_OPTS
			;;
		"help")
		opts+=$NO_OPTS
			;;
	esac

	COMPREPLY+=( $( compgen $compargs -W "$opts" -- $cur ) )

	return 0
}

plugin_ocp_opts () {
    local opts=""
	local compargs=""

	local nonopt_args=0
	for (( i=0; i < ${#words[@]}-1; i++ )); do
		if [[ ${words[i]} != -* ]]; then
			let nonopt_args+=1
		fi
	done

	if [ $nonopt_args -eq 3 ]; then
		opts="/dev/nvme* "
	fi

	opts+=" "

	case "$1" in
		"smart-add-log")
		opts+=" --output-format= -o"
			;;
		"latency-monitor-log")
		opts+=" --output-format= -o"
			;;
		"set-latency-monitor-feature")
		opts+=" --active_bucket_timer_threshold= -t \
			--active_threshold_a= -a --active_threshold_b= -b \
			--active_threshold_c= -c --active_threshold_d= -d \
			--active_latency_config= -f \
			--active_latency_minimum_window= -w \
			--debug_log_trigger_enable -r --discard_debug_log= -l \
			--latency_monitor_feature_enable= -e"
			;;
		"internal-log")
		opts+=" --telemetry_type= -t --telemetry_data_area= -a \
			--output-file= -o"
			;;
		"clear-fw-activate-history")
		opts+=" --no-uuid -n"
			;;
		"eol-plp-failure-mode")
		opts+=" --mode= -m --save -s --sel= -S --no-uuid -n"
			;;
		"clear-pcie-correctable-error-counters")
		opts+=" --no-uuid -n"
			;;
		"vs-fw-activate-history")
		opts+=" --output-format= -o"
			;;
		"device-capability-log")
		opts+=" --output-format= -o"
			;;
		"help")
		opts+=$NO_OPTS
			;;
	esac

	COMPREPLY+=( $( compgen $compargs -W "$opts" -- $cur ) )

	return 0
}

_nvme_subcmds () {
	local cur prev words cword
	_init_completion || return

	# Constant to indicate command has no options
	NO_OPTS=""

	# Associative array of plugins and associated subcommands
	# Order here is same as PLUGIN_OBJS in Makefile
	typeset -Ar _plugin_subcmds=(
		[intel]="id-ctrl internal-log lat-stats \
			set-bucket-thresholds lat-stats-tracking \
			market-name smart-log-add temp-stats"
		[amzn]="id-ctrl"
		[memblaze]="smart-log-add get-pm-status set-pm-status \
			select-download lat-stats lat-stats-print lat-log \
			lat-log-print clear-error-log"
		[wdc]="cap-diag drive-log get-crash-dump get-pfail-dump \
			id-ctrl purge purge-monitor vs-internal-log \
			vs-nand-stats vs-smart-add-log clear-pcie-correctable-errors \
			drive-essentials get-drive-status clear-assert-dump \
			drive-resize vs-fw-activate-history clear-fw-activate-history \
			enc-get-log vs-telemetry-controller-option \
			vs-error-reason-identifier log-page-directory \
			namespace-resize vs-drive-info vs-temperature-stats \
			capabilities cloud-SSD-plugin-version vs-pcie-stats"
		[huawei]="list id-ctrl"
		[netapp]="smdevices ontapdevices"
		[toshiba]="vs-smart-add-log vs-internal-log \
			clear-pcie-correctable-errors"
		[micron]="select-download vs-temperature-stats vs-pcie-stats \
			clear-pcie-correctable-errors vs-internal-log \
			vs-telemetry-controller-option vs-nand-stats \
			vs-drive-info plugin-version cloud-SSD-plugin-version \
			log-page-directory vs-fw-activate-history \
			vs-error-reason-identifier vs-smart-add-log \
			clear-fw-activate-history vs-smbus-option"
		[seagate]="vs-temperature-stats vs-log-page-sup \
			vs-smart-add-log vs-pcie-stats clear-pcie-correctable-errors \
			get-host-tele get-ctrl-tele vs-internal-log \
			plugin-version"
		[virtium]="save-smart-to-vtview-log show-identify"
		[shannon]="smart-log-add get-feature-add set-feature-add id-ctrl"
		[dera]="smart-log-add"
		[sfx]="smart-log-add lat-stats get-bad-block query-cap \
			change-cap set-feature get-feature"
		[transcend]="healthvalue badblock"
		[zns]="id-ctrl id-ns zone-mgmt-recv \
			zone-mgmt-send report-zones close-zone \
			finish-zone open-zone reset-zone offline-zone \
			set-zone-desc zone-append changed-zone-list"
		[nvidia]="id-ctrl"
		[ymtc]="smart-log-add"
		[inspur]="nvme-vendor-log"
		[ocp]="smart-add-log latency-monitor-log \
			set-latency-monitor-feature internal-log \
			clear-fw-activate-history eol-plp-failure-mode \
			clear-pcie-correctable-error-counters \
			vs-fw-activate-history device-capability-log"
	)

	# Associative array mapping plugins to coresponding option completions
	typeset -Ar _plugin_funcs=(
		[intel]="plugin_intel_opts"
		[amzn]="plugin_amzn_opts"
		[memblaze]="plugin_memblaze_opts"
		[wdc]="plugin_wdc_opts"
		[huawei]="plugin_huawei_opts"
		[toshiba]="plugin_toshiba_opts"
		[micron]="plugin_micron_opts"
		[seagate]="plugin_seagate_opts"
		[virtium]="plugin_virtium_opts"
		[shannon]="plugin_shannon_opts"
		[dera]="plugin_dera_opts"
		[sfx]="plugin_sfx_opts"
		[transcend]="plugin_transcend_opts"
		[zns]="plugin_zns_opts"
		[nvidia]="plugin_nvidia_opts"
		[ymtc]="plugin_ymtc_opts"
		[inspur]="plugin_inspur_opts"
		[ocp]="plugin_ocp_opts"
	)

	# Top level commands
	_cmds="list list-subsys id-ctrl id-ns \
		id-ns-granularity list-ns list-ctrl \
		id-ns-lba-format nvm-id-ns nvm-id-ns-lba-format \
		nvm-id-ctrl primary-ctrl-caps list-secondary \
		ns-descs id-nvmset id-uuid id-iocs id-domain create-ns \
		delete-ns get-ns-id get-log telemetry-log \
		fw-log changed-ns-list-log smart-log ana-log \
		error-log effects-log endurance-log \
		predictable-lat-log pred-lat-event-agg-log \
		persistent-event-log endurance-agg-log \
		lba-status-log resv-notif-log get-feature \
		device-self-test self-test-log set-feature \
		set-property get-property format fw-commit \
		fw-download admin-passthru io-passthru \
		security-send security-recv get-lba-status \
		resv-acquire resv-register resv-release \
		resv-report dsm copy flush compare read \
		write write-zeros write-uncor verify \
		sanitize sanitize-log reset subsystem-reset \
		ns-rescan show-regs discover connect-all \
		connect disconnect disconnect-all gen-hostnqn \
		show-hostnqn dir-receive dir-send virt-mgmt \
		rpmb boot-part-log fid-support-effects-log \
		supported-log-pages lockdown media-unit-stat-log \
		supported-cap-config-log dim show-topology list-endgrp"

	# Add plugins:
	for plugin in "${!_plugin_subcmds[@]}"; do
		_cmds+=" $plugin"
	done

	cmds+=" version help"

	if [[ ${#words[*]} -lt 3 ]]; then
		COMPREPLY+=( $(compgen -W "$_cmds" -- $cur ) )
	else
		for subcmd in "${!_plugin_subcmds[@]}"; do
			if [[ ${words[1]} == $subcmd ]]; then
				if [[ ${#words[*]} -lt 4 ]]; then
					COMPREPLY+=( $(compgen -W "${_plugin_subcmds[$subcmd]}" -- $cur ) )
				else
					func=${_plugin_funcs[$subcmd]}
					$func ${words[2]} $prev
				fi
				return 0
			fi
		done

		nvme_list_opts ${words[1]} $prev
	fi

	return 0
}

complete -o default -F _nvme_subcmds nvme
