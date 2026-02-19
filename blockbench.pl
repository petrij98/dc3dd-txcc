#!/usr/bin/perl

# blockbench.pl - block-size benchmarking script
# DC3/DCCI
# Andrew Medico <andrew.medico.ctr@dc3.mil>

use strict;
use warnings;

use Getopt::Long;

my $num_trials = 3;
my $sectors = 10000;
my $dd = "/usr/local/bin/dc3dd";

my $help = 0;

my $res = GetOptions("trials=i"  => \$num_trials,
                     "sectors=i" => \$sectors,
                     "dd=s"      => \$dd,
                     "help"      => \$help);

if ($help || not defined $ARGV[0])
{
    print <<END;
Usage: $0 [OPTIONS] device

dc3dd Block Size Benchmark
This script attempts to find the optimum block size for drive imaging by trying
a range of block size values.

  --dd=PATH    Use dc3dd binary PATH [default: /usr/local/bin/dc3dd]
  --trials=N   Average the times of N trials [default: 3]
  --sectors=N  Read N sectors. Increase for fast devices if trials complete
               too quickly for accurate timing, and decrease for slow devices
               if trials take too long. [default: 10000]
  --help       Show this help
END
exit;
}

my $dev = $ARGV[0];

my $pc = $sectors * 10;
my @sizes = qw(512 1024 2048 4096 8192 16384 32768 65536 131072 262144 524288 1048576);
my %rates;


print "Testing $dev:\n";
print "Trials: $num_trials\n";
print "Sectors: $sectors\n";
print "\n";

my $direct_opt = "";
if ($^O !~ /darwin/i)
{
    $direct_opt = "iflag=direct";
}

# for each candidate size
for my $size (@sizes)
{
    print "bs=$size, trial";
    my @trials;
    # do multiple trials for a good average
    for (1 .. $num_trials)
    {
        print " $_"; 
        my $out = `$dd if=$dev of=/dev/null bs=$size $direct_opt conv=sync,noerror count=$sectors progresscount=$pc 2>&1`;
        # 102400000 bytes (98 M) copied (100%), 0.803168 s, 122 M/s
        if ($out =~ /(\d+) bytes .+ (\d+\.\d+) s/)
        {
            push(@trials, $1/$2);
        }
        else
        {
            die "\ndc3dd execution failed - output was:\n$out\n";
        }
    }
    print "\n";

    $rates{$size} = average(@trials);
}

print "\nResults:\n";

my ($bs, $rate, $speedup);

format STDOUT =
bs=@#######, avg rate @######### B/s (@#X)
$bs, $rate, $speedup
.

my $base = $rates{512};

for $bs (sort {$rates{$b} <=> $rates{$a}} keys %rates)
{
    $rate = $rates{$bs};
    $speedup = $rate / $base;
    write;
}

sub average
{
    my $total = 0;
    map { $total += $_} @_;
    return $total / ($#_+1);
}

