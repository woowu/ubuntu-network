#!/usr/bin/node --harmony
'require strict';

const fs = require('fs');
const os = require('os');
const spawn = require('child_process').spawn;

const command_help = {
    'extract-all': 'Extrace route and name resolve inforation from the pcap'
        + ' traffics file. It then create two script used for adding'
        + ' and removing these route entries to/from a network interface.'
        + ' A Unix hosts file also created for holding name resolution'
        + ' information.',
    'print-hosts': 'print hosts in the pcap file',
};

const activeHosts = [];
const inactiveHosts = [];

var file;
var nif;
var domain;
var localIps;
var gateway;
var skipWs;

const getLocalIps = nif => {
    const descList = os.networkInterfaces()[nif];
    const addresses = [];

    if (! descList) return null;
    descList.forEach(desc => {
        if (desc.family != 'IPv4') return;
        addresses.push(desc.address);
    });
    return addresses;
};

const getGatewayIp = (nif, cb) => {
    const iproute = spawn('ip', ['route', 'show']);
    const stdout = require('readline').createInterface({
        input: iproute.stdout,
    });
    const pat = /default via ([0-9.]+) dev ([^\s]+).*/;

    var gw;
    stdout.on('line', line => {
        const match = line.match(pat);
        if (! match || match[2] != nif) return;
        gw = match[1];
    });
    stdout.on('close', () => {
        cb(null, gw);
    });
};

/**
 * From the pcap file, extract all the IP address as IP sender or receiver,
 * then return an unique list of all the appeared IPs.
 */
const extractHosts = cb => {
    const tcpdump = spawn('tcpdump', ['-r', file, '-nn', 'ip']);
    const stdout = require('readline').createInterface({
        input: tcpdump.stdout,
    });
    const stderr = require('readline').createInterface({
        input: tcpdump.stderr,
    });

    const summary = /^[0-9:.]+ IP ([0-9.]+) [<>] ([0-9.]+).*/;
    const ips = new Set();

    const parseLine = line => {
        var ip;
        const match = line.match(summary);

        if (! match) return;
        for (var i = 1; i < 2; ++i) {
            /* it could be an ip or ip.port */
            if (match[i].split('.').length == 4)
                ip = match[i];
            else
                ip = match[i].split('.').slice(0, 4).join('.');
            if (! localIps || ! localIps.includes(ip))
                ips.add(ip);
        }
    };

    stdout.on('line', parseLine);
    stdout.on('close', () => {
        cb(null, Array.from(ips));
    });
    stderr.on('line', line => {
        if (line.search(/^reading from file/) != 0)
            console.error(line);
    });
}

/* If I received from an IP of UDP or TCP data, I then consider the IP address
 * is active.
 */
const isHostActive = (ip, cb) => {
    const args = [
        '-r',
        file,
        '-nn',
        'src',
        'host',
        ip,
        'and (',
        'udp',
        'or',
        '( tcp',
        'and',
        'tcp[tcpflags] & (tcp-rst|tcp-syn|tcp-fin) == 0 ))',
    ];
    const tcpdump = spawn('tcpdump', args);
    const stdout = require('readline').createInterface({
        input: tcpdump.stdout,
    });
    const stderr = require('readline').createInterface({
        input: tcpdump.stderr,
    });

    var packets = 0;
    stdout.on('line', line => {
        ++packets;
    });
    stdout.on('close', () => {
        cb(null, packets > 0);
    });
    stderr.on('line', line => {
        if (line.search(/^reading from file/) != 0)
            console.error(line);
    });
};

/**
 * Go through a list of IPs, and returns back two lists, one is the active IP
 * lists, the other is the inactive IP lists.
 */
const hostsPreProcess = (ips, cb) => {
    const activeHosts = [];
    const inactiveHosts = [];
    const excludeHosts = [
        /^0\.0\.0\./,
        /^172\.217\.24\./,
        /^172\.217\.27\./,
        /^172\.217\.160\./,
    ];

    const shouldSkipHost = ip => {
        for (var i = 0; i < excludeHosts.length; ++i) 
            if (ip.search(excludeHosts[i]) >= 0)
                return true;
        return false;
    };

    const process = ips => {
        if (! ips.length) return cb(null, activeHosts, inactiveHosts);

        const ip = ips[0];
        const remaining = ips.slice(1);

        if (shouldSkipHost(ip)) {
            skipWs.write(`${ip}\n`);
            process(remaining);
        } else
            isHostActive(ip, (err, active) => {
                if (active)
                    activeHosts.push(ip);
                else
                    inactiveHosts.push(ip);
                process(remaining);
            });
    };

    process(ips);
};

/**
 * From a list of ips, by query the pcap file, to generate a list of text
 * lines, each of which is a name-resove like: 'ip a.b.com c.x.org'
 */
const extractNameResolve = (hosts, cb) => {
    const tcpdump = spawn('tcpdump', ['-r', file, '-nn', 'udp', 'port', '53']);
    const rl = require('readline').createInterface({
        input: tcpdump.stdout,
    });

    const query = /.*\s>\s[0-9.]+\.53:\s([0-9]+)\+.*\sA\?\s([^\s]+)\.\s.*/;
    const answer = /.*\s[0-9.]+\.53\s>\s[0-9.]+:\s([0-9]+)\s[^\s]+\s(.*)/;
    const dnsLines = [];
    var resolveLines = [];
    const queries = new Map();

    /* Each DNS answer could returns more than one names and more than one IPs.
     * For each IPs, I have to check wether I've received real traffics from
     * it. For all the reamining IPs that passed my check, I then build one or
     * more hosts-file lines that associate IPs and names.
     */
    const dnsAnswerToResolveLines = (queryId, answer) => {
        if (! queries.has(queryId)) return [];

        const ipPattern = /^([0-9.]+),?$/;
        const names = [queries.get(queryId)];
        const ips = [];
        var state = 'unknown';
        var name;

        answer.split(/\s+/).forEach(t => {
            t = t.trim();
            switch (state) {
                case 'unknown':
                    if (t == 'CNAME')
                        state = 'cname';
                    else if (t == 'A')
                        state = 'a';
                    break;
                case 'cname':
                    if (t == 'A')
                        state = 'a';
                    else if (t != 'CNAME') {
                        name = t.split(',')[0];
                        name = name.slice(0, name.length - 1);
                        names.push(name);
                    }
                    break;
                case 'a':
                    var match = t.match(ipPattern);
                    if (match) {
                        ips.push(match[1]);
                    } else if (t != 'A')
                        state = 'unknown';
                    break;
            }
        });

        const resolves = [];
        ips.forEach(ip => {
            var resolveLine = ip;
            names.forEach((name, i) => {
                if (! i)
                    resolveLine += `\t\t${name}`
                else
                    resolveLine += ` ${name}`
            });
            resolves.push(resolveLine);
        });

        return resolves;
    };

    const parseDnsLine = line => {
        const queryMatch = line.match(query);
        const answerMatch = line.match(answer);

        if (queryMatch)
            queries.set(queryMatch[1], queryMatch[2]);
        else if (answerMatch)
            resolveLines = resolveLines
                .concat(dnsAnswerToResolveLines(
                    answerMatch[1], answerMatch[2].trim()));
    };

    rl.on('line', line => {
        dnsLines.push(line);
    });
    rl.on('close', () => {
        dnsLines.forEach(parseDnsLine);
        cb(null, resolveLines);
    });
}

const handleExtractedHosts = hosts => {
    const saveHostList = (list, name) => {
        const ws = fs.createWriteStream(`./${name}`);
        list.forEach(e => {
            ws.write(`${e}\n`);
        });
        ws.end();
    };
    const saveNameResolves = list => {
        const ws = fs.createWriteStream(`./name-resolve.${domain}.${nif}`);
        const blacklist = [
            /\bgoogle.com\b/,
            /\bgoogleapis.com\b/,
            /\blastpass.com\b/,
            /\bmicrosoftonline.com\b/,
            /\bmicrosoft.com\b/,
            /\bdropbox.com\b/,
        ];
        const whitelist = [
            /landisgyr/,
            /bm\.net/,
            /microsoft/,
            /officeapps/,
            /office.com/,
            /live\.com/,
            /login\.msa\.msidentity\.com/,
            /lg\.prod\./,
            /office\.net/,
            /teams-/,
            /skype/,
            /emea\./,
            /azure\.com/,
            /msftauth\.net/,
            /msauthimages\.net/,
            /expressapisv2\.net/,
        ];
        list.forEach(line => {
            //var exclude = false;
            var include = false;
            //blacklist.forEach(p => {
            //    if (line.match(p)) exclude = true;
            //});
            whitelist.forEach(p => {
                if (line.toLowerCase().match(p))
                    include = true;
            });
            //if (! exclude) ws.write(`${line}\n`);
            if (include)
                ws.write(`${line}\n`);
            else
                skipWs.write(`${line}\n`);
        });
        ws.end();
    };
    const saveRouteTable = (networkList, gateway, nif) => {
        const ws1 = fs.createWriteStream(`./route-table-add.${domain}.${nif}`,
            {mode: 0o755});
        const ws2 = fs.createWriteStream(`./route-table-del.${domain}.${nif}`,
            {mode: 0o755});
        ws1.write('#!/bin/sh\n');
        ws2.write('#!/bin/sh\n');
        networkList.forEach(dst => {
            ws1.write(`ip route add ${dst} via \$1 dev \$2\n`);
            ws2.write(`ip route del ${dst} via \$1 dev \$2\n`);
        });
        ws1.end();
        ws2.end();
    };
    const hostsToNetworkList = hosts => {
        const networks = new Set();
        var network;
        hosts.forEach(ip => {
            network = ip.split('.').slice(0, 3).join('.') + '.0/24';
            networks.add(network);
        });
        return Array.from(networks);
    };

    console.log(`ttl ${hosts.length} hosts found`);
    skipWs = fs.createWriteStream(`./skip.${domain}.${nif}`);
    hostsPreProcess(hosts, (err, activeHosts, inactiveHosts) => {
        saveHostList(activeHosts, `active-hosts.${domain}.${nif}`);
        saveHostList(inactiveHosts, `inactive-hosts.${domain}.${nif}`);

        saveRouteTable(hostsToNetworkList(activeHosts), gateway, nif);

        extractNameResolve(activeHosts, (err, nameResolves) => {
            saveNameResolves(nameResolves);
            skipWs.end();
        });
    });
};

const extractAll = () => {
    localIps = getLocalIps(nif);

    if (! localIps || ! localIps.length)
        throw new Error(`${nif} not asssigned with ip address`);

    getGatewayIp(nif, (err, gw) => {
        if (err) throw err;
        gateway = gw;
        console.log(`gateway on ${nif} is ${gateway}`);

        extractHosts((err, hosts) => {
            if (err) throw err;
            handleExtractedHosts(hosts);
        });
    });
};

const ipToNum = ip => {
    return ip.split('.').reduce((acc, curr) => {
        return +acc * 256  + (+curr);
    }, 0); 
};

require('yargs')
    .command('extract-all file', command_help['extract-all'], yargs => {
        yargs
            .option('interface', {
                alias: 'i',
                description: 'network interface name used to create route entries',
            })
            .option('domain', {
                alias: 'd',
                description: 'domain name that will be used as suffix for generated files',
            })
            .positional('file', {
                describe: 'pcap file',
            })
            .demandOption(['interface', 'domain']);
    }, argv => {
        file = argv.file;
        nif = argv.interface;
        domain = argv.domain;
        extractAll();
    })
    .command('print-hosts file', command_help['print-hosts'], yargs => {
        yargs
            .positional('file', {
                describe: 'pcap file',
            })
    }, argv => {
        file = argv.file;
        extractHosts((err, hosts) => {
            if (err) throw err;
            hosts.sort((a, b) => {
                return ipToNum(a) - ipToNum(b);
            });
            hosts.forEach(h => {
                console.log(h);
            });
        });
    })
    .help('h')
    .alias('h', 'help')
    .argv;
