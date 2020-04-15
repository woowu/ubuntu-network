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
        description: 'usage',
    })
    .argv

const file = argv.file;
const localIps = argv.localIp.split(',');
const gateway = argv.gateway;
const nif = argv.interface;

if (! file) {
    console.error('no pcap file provided');
    process.exit(1);
}
if (! localIps.length) {
    console.error('no local ip address provided');
    process.exit(1);
}
if (! gateway) {
    console.error('no gateway provided');
    process.exit(1);
}
if (! nif) {
    console.error('not network interface name provided');
    process.exit(1);
}

const hostsStatus = new Map();

const extractExternalIps = (ipFilter, cb) => {
    const tcpdump = spawn('tcpdump', ['-r', file, '-nn', 'ip']);
    const rl = require('readline').createInterface({
        input: tcpdump.stdout,
    });

    const summary = /^[0-9:.]+ IP ([0-9.]+) [<>] ([0-9.]+).*/;
    const ips = new Set();
    const extIps = [];
    var ip;

    const extractIps = line => {
        const match = line.match(summary);
        if (! match) return;
        for (var i = 1; i < 2; ++i) {
            /* it could be an ip or ip.port */
            if (match[i].split('.').length == 4)
                ip = match[i];
            else
                ip = match[i].split('.').slice(0, 4).join('.');
            ips.add(ip);
        }
    };

    const handleIps = ips => {
        ips.forEach(ip => {
            if (! localIps.includes(ip)) extIps.push(ip);
        });
        const networks = new Set();
        var network;
        extIps.forEach(ip => {
            network = ip.split('.').slice(0, 3).join('.') + '.0/24';
            networks.add(network);
        });
        cb(null, Array.from(networks));
    };

    const doFilterIps = (ips, result, cb) => {
        if (! ips.length) return cb(result);

        const ip = ips[0];
        const remaining = ips.slice(1);

        ipFilter(ip, (err, passed) => {
            if (passed) result = [...result, ip];
            doFilterIps(remaining, result, cb);
        });
    };

    const filterIps = () => {
        doFilterIps(Array.from(ips), [], result => {
            handleIps(result);
        });
    };

    rl.on('line', extractIps);
    rl.on('close', filterIps);
}

const extractDnsRecords = (ipFilter, cb) => {
    const tcpdump = spawn('tcpdump', ['-r', file, '-nn', 'udp', 'port', '53']);
    const rl = require('readline').createInterface({
        input: tcpdump.stdout,
    });
    const queries = new Map();

    /* Each DNS answer could returns more than one names and more than one IPs.
     * For each IPs, I have to check wether I've received real traffics from
     * it. For all the reamining IPs that passed my check, I then build one or
     * more hosts-file lines that associate IPs and names.
     */
    const parseDnsAnswer = (queryId, answer, cb) => {
        if (! queries.has(queryId)) return cb(null, []);

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

        const buildHostLinesFromIpList = (ipList, result, cb) => {
            if (! ipList.length) return cb(result);

            const ip = ipList[0];
            const remaining = ipList.slice(1);

            ipFilter(ip, (err, passed) => {
                if (passed) {
                    var hostLine = ip;
                    names.forEach((name, i) => {
                        if (! i)
                            hostLine += `\t\t${name}`
                        else
                            hostLine += ` ${name}`
                    });
                    result = [...result, hostLine];
                }
                buildHostLinesFromIpList(remaining, result, cb);
            });
        };

        buildHostLinesFromIpList(ips, [], result => {
            cb(null, result);
        });
    };

    const query = /.*\s>\s[0-9.]+\.53:\s([0-9]+)\+.*\sA\?\s([^\s]+)\.\s.*/;
    const answer = /.*\s[0-9.]+\.53\s>\s[0-9.]+:\s([0-9]+)\s[^\s]+\s(.*)/;

    const handleDnsLines = (dnsLines, result, cb) => {
        if (! dnsLines.length) return cb(null, result);

        const dnsLine = dnsLines[0];
        const remainingLines = dnsLines.slice(1);

        const queryMatch = dnsLine.match(query);
        const answerMatch = dnsLine.match(answer);

        if (queryMatch) {
            queries.set(queryMatch[1], queryMatch[2]);
            handleDnsLines(remainingLines, result, cb);
        } else if (answerMatch) {
            parseDnsAnswer(answerMatch[1], answerMatch[2].trim(),
                (err, hostLines) => {
                    if (hostLines.length)
                        result = [...result, ...hostLines];
                    handleDnsLines(remainingLines, result, cb);
                }
            );
        } else
            handleDnsLines(remainingLines, result, cb);
    };

    const dnsLines = [];
    rl.on('line', line => {
        dnsLines.push(line);
    });
    rl.on('close', () => {
        handleDnsLines(dnsLines, [], (err, hostLines) => {
            cb(null, hostLines);
        });
    });
}

const isHostActive = (ip, cb) => {
    if (hostsStatus.has(ip))
        return cb(null, hostsStatus.get(ip) == 'active');

    /* If I received from an IP of UDP or TCP data, I then consider the IP address
     * is active.
     */
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
        hostsStatus.set(ip, packets > 0 ? 'active' : 'inactive');
        cb(null, packets > 0);
    });
    stderr.on('line', line => {
        if (line.search(/^reading from file/) != 0)
            console.error(line);
    });
};

extractExternalIps(isHostActive, (err, routeDsts) => {
    const ws = fs.createWriteStream('./routes.in');
    routeDsts.forEach(dst => {
        ws.write(`sudo ip route add ${dst} via ${gateway} dev ${nif}\n`);
    });
    ws.end();

    extractDnsRecords(isHostActive, (err, hostLines) => {
        const ws = fs.createWriteStream('./hosts.in');
        hostLines.forEach(line => {
            ws.write(`${line}\n`);
        });
        ws.end();

        const activeWs = fs.createWriteStream('./active-hosts');
        const inactiveWs = fs.createWriteStream('./inactive-hosts');

        hostsStatus.forEach((value, key) => {
            var ws = value == 'active' ? activeWs : inactiveWs;
            ws.write(`${key}\n`);
        });
        activeWs.end();
        inactiveWs.end();
    });
});
