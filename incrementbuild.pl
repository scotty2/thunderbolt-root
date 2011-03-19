#!/usr/bin/perl

use strict;
use warnings;

my $build = 1;
my $file;

if(open($file, "build-number.h"))
{
    ($build) = <$file> =~ /^\#define BUILD_NUMBER (\d+)$/;
    print "$build -> ";
    $build++;
    print "$build\n";
}

close $file;
open($file, ">", "build-number.h") or die "Couldn't open build-number.h for writing.";

print $file "#define BUILD_NUMBER $build\n";
close $file;

