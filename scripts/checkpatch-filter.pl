#!/usr/bin/perl
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Read checkpatch output on stdin and drop known false positives.
# Exit 1 if an ERROR or WARNING remains.
#
# checkpatch does not recognize __cleanup_* declarations as variable
# declarations. It reports "Missing a blank line after declarations"
# when one is next to another declaration.
#
# A test prints its own name. checkpatch reports the literal name and
# suggests __func__. With __func__, checkpatch reports "Unnecessary
# ftrace-like logging". No form passes, so drop the first warning for
# files in a tests/ directory.

use strict;
use warnings;

my $found = 0;

while (my $line = <STDIN>) {
	if ($line =~ /^WARNING: Missing a blank line after declarations/) {
		my $context = <STDIN> // '';
		my $prev = <STDIN> // '';
		my $cur = <STDIN> // '';

		next if $prev =~ /__cleanup/ || $cur =~ /__cleanup/;
		$line .= $context . $prev . $cur;
	}
	if ($line =~ /^WARNING: Prefer using '"%s\.\.\.", __func__'/) {
		my $file = <STDIN> // '';
		my $code = <STDIN> // '';
		my $blank = <STDIN> // '';

		next if $file =~ m{^#\d+: FILE: (?:.*/)?tests/};
		$line .= $file . $code . $blank;
	}
	$found = 1 if $line =~ /^(ERROR|WARNING):/;
	print $line;
}

exit $found;
