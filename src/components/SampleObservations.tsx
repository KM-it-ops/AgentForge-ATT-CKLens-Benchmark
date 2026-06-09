type Sample = {
  label: string;
  type: "log" | "alert" | "nmap" | "packet" | "soc" | "other";
  text: string;
};

export const SAMPLES: Sample[] = [
  {
    label: "Nmap scan summary",
    type: "nmap",
    text: `# Nmap 7.94 scan report for lab-host-03 (10.20.0.45)
Host is up (0.0021s latency).
PORT      STATE  SERVICE     VERSION
22/tcp    open   ssh         OpenSSH 8.9
80/tcp    open   http        nginx 1.24
139/tcp   open   netbios-ssn Samba 4.15
445/tcp   open   microsoft-ds Samba 4.15
3389/tcp  open   ms-wbt-server (closed by RST)
Scan initiated from 10.20.0.7 — 1000 ports scanned in 4.2s.`,
  },
  {
    label: "Windows 4625 burst (synthetic)",
    type: "log",
    text: `2025-06-08T14:02:11Z host=WIN-LAB-12 EventID=4625 TargetUserName=admin LogonType=3 Source=10.20.0.99 Status=0xC000006D SubStatus=0xC000006A
2025-06-08T14:02:13Z host=WIN-LAB-12 EventID=4625 TargetUserName=admin LogonType=3 Source=10.20.0.99 Status=0xC000006D
2025-06-08T14:02:14Z host=WIN-LAB-12 EventID=4625 TargetUserName=svc_backup LogonType=3 Source=10.20.0.99
2025-06-08T14:02:16Z host=WIN-LAB-12 EventID=4625 TargetUserName=guest LogonType=3 Source=10.20.0.99
(40 similar events in 18 seconds)`,
  },
  {
    label: "SOC incident note",
    type: "soc",
    text: `Analyst note (lab): EDR flagged powershell.exe on WS-204 spawning from winword.exe at 09:14.
Process command line included '-NoP -W Hidden -Enc <base64>'. Outbound TCP/443 to 198.51.100.22 immediately after.
No prior alerts on this host. User reported opening an emailed invoice attachment.`,
  },
  {
    label: "Packet capture note",
    type: "packet",
    text: `Wireshark capture from lab segment 10.30.0.0/24, 5 min window.
Observed: repeated DNS TXT queries to *.weirdlongsubdomain.example.test from 10.30.0.51, ~1 query/sec, average 180 byte responses.
No matching A/AAAA traffic. Host normally only does HTTP/HTTPS.`,
  },
];
