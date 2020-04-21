#!/usr/bin/node --harmony
'require strict';

const fs = require('fs');
const spawn = require('child_process').spawn;

const argv = require('yargs')
    .option('file', {
        alias: 'f',
        description: 'pcap file',
    })
    .option('local-ip', {
        alias: 'l',
        descriptions: 'comma-separated list of local IP\'s',
    })
    .option('gateway', {
        alias: 'g',
        description: 'gateway IP used to create route entries',
    })
    .option('interface', {
        alias: 'i',
        description: 'network interface name used to create route entries',
    })
    .option('help', {
        alias: 'h',
        description: 'Extrace route and name resolve inforation from a pcap'
            + ' traffics file. It then create two script used for adding'
            + ' and removing these route entries to/from a network interface.'
            + ' A Unix hosts file also created for holding name resolution'
            + ' information.',
    })
    .argv

if (! argv.file) {
    console.error('no pcap file provided');
    process.exit(1);
}
if (! argv.localIp) {
    console.error('no local ip address provided');
    process.exit(1);
}
if (! argv.gateway) {
    console.error('no gateway provided');
    process.exit(1);
}
if (! argv.i) {
    console.error('no network interface name provided');
    process.exit(1);
}

const file = argv.file;
const localIps = argv.localIp.split(',');
const gateway = argv.gateway;
const nif = argv.interface;

const activeHosts = [];
const inactiveHosts = [];

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
            if (! localIps.includes(ip))
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

    const process = ips => {
        if (! ips.length) return cb(null, activeHosts, inactiveHosts);

        const ip = ips[0];
        const remaining = ips.slice(1);

        if (ip.search(/^0\.0\.0\./) == 0) {
            console.log(`skip ${ip}`);
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

extractHosts((err, hosts) => {
    const saveHostList = (list, name) => {
        const ws = fs.createWriteStream(`./${name}`);
        list.forEach(e => {
            ws.write(`${e}\n`);
        });
        ws.end();
    };
    const saveNameResolves = list => {
        const ws = fs.createWriteStream(`./name-resolve`);
        const excludePatterns = [
            /\bgoogle.com\b/,
            /\bgoogleapis.com\b/,
        ];
        list.forEach(line => {
            var exclude = false;
            console.log(line);
            excludePatterns.forEach(p => {
                if (line.match(p)) exclude = true;
            });
            if (! exclude) ws.write(`${line}\n`);
        });
        ws.end();
    };
    const saveRouteTable = (networkList, gateway, nif) => {
        const ws1 = fs.createWriteStream('./route-table-add', {mode: 0o755});
        const ws2 = fs.createWriteStream('./route-table-del', {mode: 0o755});
        ws1.write('#!/bin/sh\n');
        ws2.write('#!/bin/sh\n');
        networkList.forEach(dst => {
            ws1.write(`ip route add ${dst} via ${gateway} dev ${nif}\n`);
            ws2.write(`ip route del ${dst} via ${gateway} dev ${nif}\n`);
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
    hostsPreProcess(hosts, (err, activeHosts, inactiveHosts) => {
        saveHostList(activeHosts, 'active-hosts');
        saveHostList(inactiveHosts, 'inactive-hosts');

        saveRouteTable(hostsToNetworkList(activeHosts), gateway, nif);

        extractNameResolve(activeHosts, (err, nameResolves) => {
            saveNameResolves(nameResolves);
        });
    });
});