#!/usr/bin/perl
#文件：getproxy.pl
#用途：通过搜索引擎获取当前可用的HTTP/Socks5代理
#作者：watercloud (watercloud@xfocus.org watercloud@nsfocus.com)
#编写：2005-6-23
#更新：2005-11-5

# update by zz@nsfocus
# add qqwry.dat support

# add check anonymous proxy

use strict;
use Data::Dump qw(dump);
use LWP::UserAgent;
use HTML::LinkExtor;
use URI::URL; 
use URI::Escape;
use Getopt::Long;
use threads;
use threads::shared;
use Thread::Semaphore; #down up
use IO::Socket::Socks;
use IO::Select;
use Term::ANSIColor; # color print
use Encode;

my $DEBUG=1;
my $SEARCH_NUM=100;
my $GOOGLE="http://www.google.com/search?ie=UTF-8&oe=UTF-8&num=$SEARCH_NUM&q=";
my $BAIDU="http://www.baidu.com/s?rn=100&wd=";
my $BING="http://cn.bing.com/search?&go=&qs=n&sk=&form=QBLH&q=";

my $m_key="代理 每日更新 ";
my $m_test_site="www.microsoft.com";
my $m_test_port=80;
my $m_proxy_type="http";
my $m_proxy_file;
my $m_url_file;
my $m_url;
my $m_proxy;
my $m_encoding;
my $m_test_keyword="microsoft";

# update by zz@nsfocus
my($sec,$min,$hour,$day,$mon,$year) = localtime();
$year += 1900;
$mon += 1;
$m_key .= $year."-$mon";

my $m_timeout=10;
my $m_max_num=10;
my $m_thread_num=10;
my $m_raw_uri;
my $m_out_format="";

&getopts();

my $m_sem=Thread::Semaphore->new($m_thread_num);
my $m_get_num=0;
my $exit_flag=0;
share $m_get_num;
share $exit_flag;

&main();


#--------------------subs---------------
sub main
{
    my %url_hist;
    my @threads;
    my $rurls;

    if($m_proxy_file)
    {
        my $f;
        open $f,"<$m_proxy_file" or die "Open file $m_proxy_file error.";
        my @t=<$f>;
        close $f;
        exit 1 if @t == 0 ;
        print "Read file ok.\n" if $DEBUG;
        chomp @t;
        my @tds = &test_proxys(\@t);
        push @threads,@tds;
    }
    else
    {
        if($m_url_file)
        {
            my $f;
            open $f,"<$m_url_file" or die "Open file $m_url_file error.";
            my @t=<$f>; 
            close $f;
            exit 1 if @t == 0 ;
            print "Read file ok.\n" if $DEBUG;
            chomp @t;
            $rurls=\@t;
        }
        elsif($m_url)
        {
            my @t = ();
            push @t, $m_url;
            chomp @t;
            $rurls=\@t;
        }
        else
        {
            $rurls=get_proxy_pub_urls($m_raw_uri);
        }

        dump $rurls if $DEBUG >=4;

        foreach (@$rurls)
        {
            next if  exists($url_hist{$_});
            my $rproxys=get_proxys($_);
            my @t = &test_proxys($rproxys);
            push @threads,@t;
            last if $exit_flag;
        }
    }

    dump("threads:\n",@threads) if $DEBUG >=4;
    foreach (@threads)
    {
        if($exit_flag)
        {
            $_->detach();
        }
        else
        {
            $_->join();
        }
    }
}

# find where is the ip use qqwry.dat
# from internet :)
sub ipwhere {
    my $ipbegin;
    my $ipend;
    my $ipData1;
    my $ipData2;
    my $DataSeek;
    my $ipFlag;
    my $ipAddr1;
    my $ipAddr2;

    my $ip=shift;
    my @ip=split(/\./,$ip);
    my $ipNum = $ip[0]*16777216+$ip[1]*65536+$ip[2]*256+$ip[3];

    my $ipfile="./qqwry.dat";
    open(FILE,"$ipfile");
    binmode(FILE);
    sysread(FILE,$ipbegin,4);
    sysread(FILE,$ipend,4);
     $ipbegin=unpack("L",$ipbegin);
     $ipend=unpack("L",$ipend);
    my $ipAllNum = ($ipend-$ipbegin)/7+1;

    my $BeginNum=0;
    my $EndNum=$ipAllNum;

    Bgn:
    my $Middle= int(($EndNum+$BeginNum)/2);

    seek(FILE,$ipbegin+7*$Middle,0);
    read(FILE,$ipData1,4);
    my $ip1num=unpack("L",$ipData1);
    if ($ip1num > $ipNum) {
        $EndNum=$Middle;
        goto Bgn;
    }

    read(FILE,$DataSeek,3);
    $DataSeek=unpack("L",$DataSeek."\0");
    seek(FILE,$DataSeek,0);
    read(FILE,$ipData2,4);
    my $ip2num=unpack("L",$ipData2);
    if ($ip2num < $ipNum) {
        goto nd if ($Middle==$BeginNum);
        $BeginNum=$Middle;
        goto Bgn;
    }

    $/="\0";
    read(FILE,$ipFlag,1);
    if ($ipFlag eq "\1") {
        my $ipSeek;
        read(FILE,$ipSeek,3);
        $ipSeek = unpack("L",$ipSeek."\0");
        seek(FILE,$ipSeek,0);
        read(FILE,$ipFlag,1);
    }
    if ($ipFlag eq "\2") {
        my $AddrSeek;
        read(FILE,$AddrSeek,3);
        read(FILE,$ipFlag,1);
        if($ipFlag eq "\2") {
            my $AddrSeek2;
            read(FILE,$AddrSeek2,3);
            $AddrSeek2 = unpack("L",$AddrSeek2."\0");
            seek(FILE,$AddrSeek2,0);
        }
        else {
            seek(FILE,-1,1);
        }
        $ipAddr2=<FILE>;
        $AddrSeek = unpack("L",$AddrSeek."\0");
        seek(FILE,$AddrSeek,0);
        $ipAddr1=<FILE>;
    }
    else {
        seek(FILE,-1,1);
        $ipAddr1=<FILE>;
        read(FILE,$ipFlag,1);
        if($ipFlag eq "\2") {
            my $AddrSeek2;
            read(FILE,$AddrSeek2,3);
            $AddrSeek2 = unpack("L",$AddrSeek2."\0");
            seek(FILE,$AddrSeek2,0);
        }
        else {
            seek(FILE,-1,1);
        }
        $ipAddr2=<FILE>;
    }

    nd:
    chomp($ipAddr1,$ipAddr2);
    $/="\n";
    close(FILE);

    $ipAddr2="" if($ipAddr2=~/http/i);
    my $ipaddr="$ipAddr1 $ipAddr2";
    $ipaddr =~ s/CZ88\.NET//isg;
    $ipaddr="未知地区" if ($ipaddr=~/未知|http/i || $ipaddr eq "");
    return $ipaddr;
}

sub test_proxys #return @threads fun(\@proxys)
{
    my $ref=shift @_;
    my %proxy_hist;
    my @threads;
    foreach (@$ref)
    {
        next if  exists($proxy_hist{$_});
        $proxy_hist{$_}=1;
        $m_sem->down();
        print STDERR "testing $_ ...\n" if $DEBUG >2;
        my $t;
        if($m_proxy_type eq "http")
        {
            $t=threads->create("test_http_proxy",$_);
        }
        else
        {
            $t=threads->create("test_socks_proxy",$_);
        }
        push(@threads,$t) if $t;
        #如果找到的存活代理数目够了则退出
        $exit_flag=1,last if $m_get_num >= $m_max_num;  
    }
    return @threads;
}

sub filter_url
{
    dump @_ if $DEBUG >=4 ;
    return 1 if @_ != 2;
    return 1 if $_[0] !~ /^http/;
    return 1 if $_[1] !~ /^http/;
    my $uri1=URI->new($_[0]);
    my $uri2=URI->new($_[1]);
    my $host1=$uri1->host;
    my $host2=$uri2->host;
    my $key1=substr($host1,index($host1,".")+1);
    my $key2=substr($host2,index($host2,".")+1);
    return 1 if $key1 eq $key2;
    return 1 if $host1 eq $key2;

    return 1 if $_->[2] =~ /search\?q=cache/;  #google cache的标记
    return 0;
}

sub get_proxy_pub_urls  # return \@urls fun($search_site_uri)
{
    my $search_uri=shift @_;
    my $ua= LWP::UserAgent->new; #网站交互界面

    $ua->cookie_jar({});
    $ua->agent('Mozilla/4.0 (compatible; MSIE 6.0; Windws NT 5.1)');
    $ua->timeout($m_timeout*3);
    $ua->proxy("http","http://" . $m_proxy) if ($m_proxy);


    my $res_obj= $ua->get($search_uri);
    print STDERR "-->",$search_uri,"\n",$res_obj->status_line,"\n";
    exit 1 if (! $res_obj->is_success());

    my $html_parse = HTML::LinkExtor->new();
    $html_parse->parse($res_obj->as_string);

    my @urls;
    foreach ($html_parse->links)
    {
        next if $_->[0] ne "a";
        next if filter_url($search_uri,$_->[2]);
        print $_->[2]."\n" if $DEBUG>2;
        push(@urls,$_->[2]);
    }

    return \@urls;

}


sub get_proxys  #return \@proxys fun($url)
{
    my $url=shift @_;
    my @proxys;

    my $ua= LWP::UserAgent->new; #网站交互界面
    $ua->cookie_jar({});
    $ua->agent('Mozilla/4.0 (compatible; MSIE 6.0; Windws NT 5.1)');
    $ua->timeout($m_timeout*2);
    $ua->proxy("http","http://" . $m_proxy) if ($m_proxy);


    print STDERR "connecting ",$url,"  ...\n" if $DEBUG>=2;
    my $res_obj= $ua->get($url);
    print STDERR $url,"\t",$res_obj->status_line,"\n" if $DEBUG>1;
    next if (! $res_obj->is_success());

    # to do: update regexp to match multiple html format
    my $html=$res_obj->as_string;
    while($html =~ m/
        (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) #IP
        \D+
        (?<!\=.)(\d{2,5}) #PORT
        /xsg )
    {
        my $ip=$1;
        my $port=$2;
        my $proxy="$1:$2";
        #print "$proxy\n" if $DEBUG >= 3;

        pos($html);
        if($m_proxy_type eq "http")
        {
            next if $port ne "80" && $port ne "8080" && $port ne "3128";
        }
        else
        {
            next if $port eq "80" || $port eq "8080" || $port eq "3128";
        }
        push @proxys,$proxy;

    }

    return \@proxys;

}


sub test_http_proxy
{
    return if @_ == 0;
    $_=shift @_;
    my ($proxy,$port)=split /:/,$_;
    $_=$proxy . ":" . $port;
    my $ua=LWP::UserAgent->new();
    $ua->agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.132 Safari/537.36");
    $ua->timeout($m_timeout);
    $ua->proxy("http","http://" . $_);

    my $start = time;

    my $res = $ua->get('http://'. $m_test_site);
    my $t = time - $start;
    if($res->is_success())
    {
        my $html=$res->as_string;

        if($html =~ /$m_test_keyword/i)
        {
            $m_get_num++;
            if($m_out_format eq "net-trans")
            {
                print "$_\@HTTP:::$m_get_num\n";
            }
            else
            {
                if ($m_encoding)
                {
                    my $where = encode($m_encoding, 
                          decode("gbk", ipwhere("$_")));

                    printf "OK  %20s\@HTTP %20s %s\n", "$_", $where, "$t";
                }
                else
                {
                    printf "OK  %20s\@HTTP %20s %s\n","$_", ipwhere("$_"), "$t";
                }
            }
        }
    }
    $m_sem->up();
}

sub test_socks_proxy
{
    return if @_ == 0;
    $_=shift @_;
    my ($proxy,$port)=split /:/,$_;
    printf "testing %s:%s\n", $proxy, $port if $DEBUG >= 4;
    #$IO::Socket::Socks::SOCKS5_RESOLVE = 0;
    my $socks = new IO::Socket::Socks(ProxyAddr=>$proxy,
                                  ProxyPort=>$port,
                                  ConnectAddr=>$m_test_site,
                                  ConnectPort=>$m_test_port,
                                  AuthType=>"none",
                                  Timeout=>$m_timeout,
                                  SocksDebug=>0,
                                  SocksVersion=>5,
                                 ) or goto end;

    $socks->syswrite (
    "GET / HTTP/1.0\015\012".
    "Host: $m_test_site\015\012\015\012"
    );

    $socks->sysread(my $buf, 1024);
    if ($buf) {
        $m_get_num++;
        print "OK $proxy:$port\@Socks5\n";
    }

end:
    $socks->close() if $socks;
    $m_sem->up();
}

sub usage()
{
    print <<EOF
GetProxy程序使用搜索引擎来查找代理公布网站，然后从这些网站寻找代理地址，
并自动对代理进行验证。

使用: getproxy [ 选项 ]
选项:
  --aim=测试站点     默认值："www.microsoft.com"
  --aim-port=端口    默认值：80
  --timeout=超时     默认值：10 ，单位：秒
  --threads=线程个数 默认值：10
  --number=代理个数  默认值：10
  --type=代理类型    默认值：http，取值范围："http" / "socks5"
  --format=输出格式  默认值：""，目前可取："net-trans"输出"影音传送带"支持格式
  --debug=调试级别   默认值：1，取值范围：[0 5]
  --key=搜索关键字   默认值："代理 每日更新 TYPE"，TYPE为--type选项值
  --engine=搜索引擎  默认值："baidu"，可取值："google" / "baidu"
  --search-uri=搜索引擎URI
  --raw-seach-uri=搜索引擎原始URI
  --load-urls=URL列表文件
  --load-proxys=PROXY列表文件
  --encoding=终端编码, (e.g utf-8)
  --test-keyword     默认值："microsoft"
  --help
  --version

说明：
  程序使用搜索引擎进行搜索时是靠--search-uri和--key来构建搜索用的URI的，其中关键字会被编码。
  编码后的KEY和--search-uri的值组成的串等效于--raw-search-uri指定的值。
  如果指定了--engine，那么系统会使用内置的对应的search-uri。
  --search-uri指定搜索引擎的URI，这就有可能使用其他的搜索引擎，目前
    google为：$GOOGLE
    baidu为 ：$BAIDU
    bing为  ：$BING
    如果指定了该选项，那么--engine选项将失效。
  --raw-seach-uri选项也使得可以使用任何搜索引擎。
    如果指定了该选项，那么--search-uri、--key、--engine选项都将失效。
  --load-urls=URL列表文件，指定了该选项后程序将不去连接搜索引擎查找代理发布站点，而是直接从
    指定文件中读取这些站点的URL，每个URL存放在单独一行。平时可以将收集到的好的代理发布站点页
    地址存放在文件中。
  --url 提取某个网页的有效代理
  --proxy 使用HTTP代理
  --load-proxys=PROXY列表文件,指定该选项后想到于对已有的代理进行验证。每个代理存放单独一行，
    主机地址和端口间用英文冒号":"号分隔。如果是验证Socks5代理必须同时指定--type=socks5
  Windows主机用户需要注意：由于Perl对Win32线程支持不太好，在Win32上线程个数不要指定太大（如
  超过5），程序退出时会发生程序错误，但不影响程序使用 ！

示例：
  getproxy 
  getproxy  --debug=3
  getproxy  --aim=www.nsfocus.com --threads=15 --timeout=5 --number=50
  getproxy  --type=socks5 --key="socks5代理 每日更新" --engine="google"
  getproxy  --load-urls=url.txt 
  getproxy  --load-proxys=proxy.txt 
  getproxy  --load-proxys=proxy.txt  --type=socks5
  getproxy  --raw-search-uri='search.yahoo.com/search?p=%E4%BB%A3%E7%90%86+%E6%9B%B4%E6%96%B0'

编写：watercloud (watercloud\@nsfocus.com watercloud\@xfocus.org)
日期：2005-6-21   更新：2005-11-5
更新：zz\@nsfocus 2011-11-29
当前版本0.3
EOF
;
    exit 0;
}

sub getopts
{
    my $help;
    my $engine="baidu";
    my $search_uri;
    exit 1 if ! GetOptions(
        "aim=s"=>\$m_test_site,
        "aim-port=s"=>\$m_test_port,
        "timeout=i"=>\$m_timeout,
        "threads=i"=>\$m_thread_num,
        "number=i"=>\$m_max_num,
        "type=s"=>\$m_proxy_type,
        "format=s"=>\$m_out_format,
        "debug=i"=>\$DEBUG,
        "key=s"=>\$m_key,
        "engine=s"=>\$engine,
        "search-uri=s"=>\$search_uri,
        "raw-search-uri=s"=>\$m_raw_uri,
        "load-urls=s"=>\$m_url_file,
        "url=s"=>\$m_url,
        "load-proxys=s"=>\$m_proxy_file,
        "proxy=s"=>\$m_proxy,
        "encoding=s"=>\$m_encoding,
        "test-keyword=s"=>\$m_test_keyword,
        "help"=>\$help,
        "version"=>\$help,
    );

    dump($m_test_site,$m_test_port,$m_timeout,$m_thread_num,
        $m_max_num,$m_proxy_type,$m_out_format,$DEBUG,$m_key,
        $engine,$search_uri,$m_raw_uri,$m_url_file,$m_url,$m_proxy_file,
        $m_proxy,$m_encoding,$m_test_keyword
    ) if $DEBUG >=4 ;

    usage() if $help;

    if($m_max_num <=0 ) { print "ERROR: --number <=0\n",usage(); }
    if($m_timeout<=0 ) { print "ERROR: --timeout<=0\n",usage(); }
    if($m_thread_num<=0 ) { print "ERROR: --threads<=0\n",usage(); }
    if(length($m_test_site) < 3) { print "ERROR: --aim\n",usage(); }
    if($m_test_port <= 0) { print "ERROR: --aim-port\n",usage(); }
    if($m_out_format)
    {
        if($m_out_format ne "net-trans" ) { print "ERROR: --format\n",usage(); }
    }
    if($m_test_port <= 0) { print "ERROR: --aim-port\n",usage(); }
    if($m_proxy_type ne "http" && $m_proxy_type ne "socks5")
    {
        print "ERROR: --type\n",usage(); 
    }
    if($engine ne "google" && $engine ne "baidu" && $engine ne "bing")
    {
        print "ERROR: --engine\n",usage(); 
    }
    if(length($m_key) < 5) { print "ERROR: --key\n",usage(); }

    if($m_url_file)
    {
        if(! -r $m_url_file) { print "ERROR READ: --load-urls\n",usage(); }
    }
    if($m_proxy_file)
    {
        if(! -r $m_proxy_file) { print "ERROR READ: --load-proxys\n",usage(); }
    }

    if( ! defined($search_uri) || ! $search_uri)
    {
        $search_uri=$BAIDU if($engine eq "baidu");
        $search_uri=$GOOGLE if($engine eq "google");
        $search_uri=$BING if($engine eq "bing");
    }
    if (! defined($m_raw_uri) || ! $m_raw_uri)
    {
        $m_raw_uri=$search_uri . uri_escape($m_key . " " . $m_proxy_type);
    }

    $m_raw_uri = "http://" . $m_raw_uri if $m_raw_uri !~ /^http/;

}
#EOF

