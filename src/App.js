import { useState, useCallback, useRef, useEffect } from "react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, AreaChart, Area, CartesianGrid
} from "recharts";

/* ─────────────────────────────────────────────────────────
   PCAP / PCAPNG BINARY PARSER
───────────────────────────────────────────────────────── */
function parseMAC(view, o) {
  return Array.from({length:6},(_,i)=>view.getUint8(o+i).toString(16).padStart(2,"0")).join(":");
}
function parseIPv4(view, o) { return [0,1,2,3].map(i=>view.getUint8(o+i)).join("."); }
function parseIPv6(view, o) {
  const p=[];
  for(let i=0;i<16;i+=2) p.push(((view.getUint8(o+i)<<8)|view.getUint8(o+i+1)).toString(16));
  return p.join(":");
}
const PROTO_MAP={1:"ICMP",2:"IGMP",6:"TCP",17:"UDP",58:"ICMPv6",89:"OSPF",132:"SCTP"};
const TCP_FLAGS_LIST=["FIN","SYN","RST","PSH","ACK","URG"];

function parseEthernet(view, o, pktLen) {
  if(pktLen<14) return null;
  const dst=parseMAC(view,o), src=parseMAC(view,o+6);
  const et=view.getUint16(o+12,false);
  let pl={src_mac:src,dst_mac:dst,ethertype:et};
  if(et===0x0800&&pktLen>=34){
    const ihl=(view.getUint8(o+14)&0x0F)*4, proto=view.getUint8(o+14+9);
    const srcIP=parseIPv4(view,o+14+12), dstIP=parseIPv4(view,o+14+16);
    const ttl=view.getUint8(o+14+8), ipLen=view.getUint16(o+14+2,false);
    pl={...pl,protocol:PROTO_MAP[proto]||String(proto),src_ip:srcIP,dst_ip:dstIP,ttl,ip_len:ipLen};
    const tb=o+14+ihl;
    if(proto===6&&pktLen>=tb-o+20){
      const sp=view.getUint16(tb,false),dp=view.getUint16(tb+2,false);
      const fB=view.getUint8(tb+13);
      const flags=TCP_FLAGS_LIST.filter((_,i)=>fB&(1<<i)).join("+");
      const dOff=(view.getUint8(tb+12)>>4)*4;
      pl={...pl,src_port:sp,dst_port:dp,flags,payload_len:Math.max(0,ipLen-ihl-dOff)};
    } else if(proto===17&&pktLen>=tb-o+8){
      const sp=view.getUint16(tb,false),dp=view.getUint16(tb+2,false),ul=view.getUint16(tb+4,false);
      pl={...pl,src_port:sp,dst_port:dp,payload_len:ul-8};
    }
  } else if(et===0x86DD&&pktLen>=54){
    const proto=view.getUint8(o+14+6);
    const srcIP=parseIPv6(view,o+14+8),dstIP=parseIPv6(view,o+14+24);
    const plen=view.getUint16(o+14+4,false);
    pl={...pl,protocol:PROTO_MAP[proto]||String(proto),src_ip:srcIP,dst_ip:dstIP,ip_version:6,ip_len:plen};
    const tb=o+14+40;
    if((proto===6||proto===17)&&pktLen>=tb-o+4)
      pl={...pl,src_port:view.getUint16(tb,false),dst_port:view.getUint16(tb+2,false)};
  } else if(et===0x0806){ pl={...pl,protocol:"ARP"}; }
  return pl;
}

function parsePCAP(buffer){
  const view=new DataView(buffer);
  const magic=view.getUint32(0,false), le=magic===0xd4c3b2a1;
  const linkType=view.getUint32(20,le);
  let offset=24; const packets=[];
  while(offset+16<=buffer.byteLength){
    const tsSec=view.getUint32(offset,le),tsUsec=view.getUint32(offset+4,le);
    const inclLen=view.getUint32(offset+8,le),origLen=view.getUint32(offset+12,le);
    offset+=16;
    if(inclLen>65535||offset+inclLen>buffer.byteLength) break;
    const ts=tsSec+tsUsec/1e6;
    let parsed={ts,orig_len:origLen,incl_len:inclLen,protocol:"RAW"};
    if(linkType===1){const eth=parseEthernet(view,offset,inclLen); if(eth) parsed={...parsed,...eth};}
    else if(linkType===101&&inclLen>=20){
      const proto=view.getUint8(offset+9);
      parsed={...parsed,protocol:PROTO_MAP[proto]||String(proto),src_ip:parseIPv4(view,offset+12),dst_ip:parseIPv4(view,offset+16)};
    }
    packets.push(parsed); offset+=inclLen;
  }
  return packets;
}

function parsePCAPNG(buffer){
  const view=new DataView(buffer); let offset=0,le=true; const packets=[];
  while(offset+8<=buffer.byteLength){
    const bt=view.getUint32(offset,le); let bl=view.getUint32(offset+4,le);
    if(bl<12||offset+bl>buffer.byteLength) break;
    if(bt===0x0A0D0D0A){
      const bom=view.getUint32(offset+8,true); le=bom===0x1A2B3C4D;
      bl=view.getUint32(offset+4,le);
    } else if(bt===0x00000006){
      const tsHigh=view.getUint32(offset+12,le),tsLow=view.getUint32(offset+16,le);
      const ts=(tsHigh*4294967296+tsLow)/1e6;
      const captLen=view.getUint32(offset+20,le),origLen=view.getUint32(offset+24,le);
      const pktOff=offset+28;
      if(pktOff+captLen<=buffer.byteLength&&captLen<65535){
        const eth=parseEthernet(view,pktOff,captLen);
        const base={ts,orig_len:origLen,incl_len:captLen,protocol:"RAW"};
        packets.push(eth?{...base,...eth}:base);
      }
    }
    offset+=bl;
  }
  return packets;
}

function parseFile(buffer){
  const view=new DataView(buffer); if(buffer.byteLength<4) return null;
  const m=view.getUint32(0,false);
  if(m===0xa1b2c3d4||m===0xd4c3b2a1) return parsePCAP(buffer);
  if(m===0x0A0D0D0A) return parsePCAPNG(buffer);
  return null;
}

/* ─────────────────────────────────────────────────────────
   ANALYSIS
───────────────────────────────────────────────────────── */
function computeStats(packets){
  if(!packets.length) return{mean:"—",std:"—",p95:"—",median:"—",max:"—",total_bytes:0};
  const lens=packets.map(p=>p.orig_len||0), sorted=[...lens].sort((a,b)=>a-b), n=lens.length;
  const mean=lens.reduce((a,b)=>a+b,0)/n;
  const std=Math.sqrt(lens.reduce((a,b)=>a+(b-mean)**2,0)/n);
  return{mean:mean.toFixed(1),std:std.toFixed(1),p95:sorted[Math.floor(n*.95)]??sorted[n-1],median:sorted[Math.floor(n/2)],max:Math.max(...lens),total_bytes:lens.reduce((a,b)=>a+b,0)};
}

const SUSPICIOUS_PORTS=new Set([4444,1337,31337,6666,6667,4899,5900,512,513,514,1080,3128,8888]);
const REASON_TEXT={
  size_outlier:"Unusually large packet — much bigger than normal",
  high_volume:(n)=>`This device sent a lot of messages (${n} total)`,
  port_scan:(n)=>`Tried connecting to ${n} different services — possible scanning`,
  syn_flood:"Sent many connection requests without finishing — possible flood attack",
  bad_port:(p)=>`Connected to port ${p}, which is commonly used by attackers`,
  big_icmp:"Sent an oversized ping — could indicate a ping flood",
};

function detectAnomalies(packets){
  if(!packets.length) return[];
  const ipCounts={},ipPorts={},synPerDst={};
  packets.forEach(p=>{
    if(!p.src_ip) return;
    ipCounts[p.src_ip]=(ipCounts[p.src_ip]||0)+1;
    if(p.dst_port!=null){if(!ipPorts[p.src_ip])ipPorts[p.src_ip]=new Set();ipPorts[p.src_ip].add(p.dst_port);}
    if(p.flags?.includes("SYN")&&!p.flags?.includes("ACK")){const k=`${p.src_ip}→${p.dst_ip}`;synPerDst[k]=(synPerDst[k]||0)+1;}
  });
  const lens=packets.map(p=>p.orig_len||0);
  const mean=lens.reduce((a,b)=>a+b,0)/lens.length;
  const std=Math.sqrt(lens.reduce((a,b)=>a+(b-mean)**2,0)/lens.length);
  const maxIP=Math.max(...Object.values(ipCounts),0);
  return packets.map((p,i)=>{
    if(!p.src_ip) return null;
    const reasons=[]; let score=0;
    const z=std>0?Math.abs(((p.orig_len||0)-mean)/std):0;
    if(z>3){reasons.push(REASON_TEXT.size_outlier);score+=0.25;}
    if(maxIP>5&&ipCounts[p.src_ip]>maxIP*0.6){reasons.push(REASON_TEXT.high_volume(ipCounts[p.src_ip]));score+=0.3;}
    const uP=ipPorts[p.src_ip]?.size||0;
    if(uP>15){reasons.push(REASON_TEXT.port_scan(uP));score+=0.4;}
    const sk=`${p.src_ip}→${p.dst_ip}`;
    if((synPerDst[sk]||0)>10){reasons.push(REASON_TEXT.syn_flood);score+=0.35;}
    if(p.dst_port!=null&&SUSPICIOUS_PORTS.has(p.dst_port)){reasons.push(REASON_TEXT.bad_port(p.dst_port));score+=0.3;}
    if(p.protocol==="ICMP"&&(p.orig_len||0)>512){reasons.push(REASON_TEXT.big_icmp);score+=0.2;}
    score=Math.min(score,1);
    if(score===0) return null;
    return{...p,_idx:i,score:parseFloat(score.toFixed(3)),reasons,severity:score>=0.7?"critical":score>=0.5?"high":score>=0.3?"medium":"low"};
  }).filter(Boolean).sort((a,b)=>b.score-a.score);
}

/* ─────────────────────────────────────────────────────────
   FILTER
───────────────────────────────────────────────────────── */
function safe(v){return v==null?"":String(v).toLowerCase();}
function matchesFilter(p,raw){
  const q=raw.trim().toLowerCase(); if(!q) return true;
  return[safe(p.src_ip),safe(p.dst_ip),safe(p.protocol),safe(p.src_port),safe(p.dst_port),safe(p.flags),safe(p.src_mac),safe(p.dst_mac)].some(v=>v.includes(q));
}

/* ─────────────────────────────────────────────────────────
   DEMO DATA
───────────────────────────────────────────────────────── */
const DEMO_PKTS=[
  {ts:0.000,src_ip:"192.168.1.10",dst_ip:"142.250.80.46",protocol:"TCP",src_port:52341,dst_port:443,flags:"SYN",orig_len:74},
  {ts:0.012,src_ip:"142.250.80.46",dst_ip:"192.168.1.10",protocol:"TCP",src_port:443,dst_port:52341,flags:"SYN+ACK",orig_len:74},
  {ts:0.013,src_ip:"192.168.1.10",dst_ip:"142.250.80.46",protocol:"TCP",src_port:52341,dst_port:443,flags:"ACK",orig_len:66},
  {ts:0.015,src_ip:"192.168.1.10",dst_ip:"8.8.8.8",protocol:"UDP",src_port:54219,dst_port:53,flags:null,orig_len:82},
  {ts:0.017,src_ip:"8.8.8.8",dst_ip:"192.168.1.10",protocol:"UDP",src_port:53,dst_port:54219,flags:null,orig_len:158},
  {ts:0.100,src_ip:"10.0.0.3",dst_ip:"192.168.1.1",protocol:"TCP",src_port:41200,dst_port:22,flags:"SYN",orig_len:74},
  {ts:0.101,src_ip:"10.0.0.3",dst_ip:"192.168.1.1",protocol:"TCP",src_port:41201,dst_port:23,flags:"SYN",orig_len:74},
  {ts:0.102,src_ip:"10.0.0.3",dst_ip:"192.168.1.1",protocol:"TCP",src_port:41202,dst_port:80,flags:"SYN",orig_len:74},
  {ts:0.103,src_ip:"10.0.0.3",dst_ip:"192.168.1.1",protocol:"TCP",src_port:41203,dst_port:443,flags:"SYN",orig_len:74},
  {ts:0.104,src_ip:"10.0.0.3",dst_ip:"192.168.1.1",protocol:"TCP",src_port:41204,dst_port:8080,flags:"SYN",orig_len:74},
  {ts:0.105,src_ip:"10.0.0.3",dst_ip:"192.168.1.1",protocol:"TCP",src_port:41205,dst_port:4444,flags:"SYN",orig_len:74},
  {ts:0.106,src_ip:"10.0.0.3",dst_ip:"192.168.1.1",protocol:"TCP",src_port:41206,dst_port:445,flags:"SYN",orig_len:74},
  {ts:0.107,src_ip:"10.0.0.3",dst_ip:"192.168.1.1",protocol:"TCP",src_port:41207,dst_port:3389,flags:"SYN",orig_len:74},
  {ts:0.108,src_ip:"10.0.0.3",dst_ip:"192.168.1.1",protocol:"TCP",src_port:41208,dst_port:21,flags:"SYN",orig_len:74},
  {ts:0.109,src_ip:"10.0.0.3",dst_ip:"192.168.1.1",protocol:"TCP",src_port:41209,dst_port:25,flags:"SYN",orig_len:74},
  {ts:0.110,src_ip:"10.0.0.3",dst_ip:"192.168.1.1",protocol:"TCP",src_port:41210,dst_port:110,flags:"SYN",orig_len:74},
  {ts:0.111,src_ip:"10.0.0.3",dst_ip:"192.168.1.1",protocol:"TCP",src_port:41211,dst_port:143,flags:"SYN",orig_len:74},
  {ts:0.112,src_ip:"10.0.0.3",dst_ip:"192.168.1.1",protocol:"TCP",src_port:41212,dst_port:1337,flags:"SYN",orig_len:74},
  {ts:0.200,src_ip:"192.168.1.10",dst_ip:"142.250.80.46",protocol:"TCP",src_port:52341,dst_port:443,flags:"PSH+ACK",orig_len:1460},
  {ts:0.210,src_ip:"192.168.1.10",dst_ip:"142.250.80.46",protocol:"TCP",src_port:52341,dst_port:443,flags:"PSH+ACK",orig_len:1460},
  {ts:0.300,src_ip:"192.168.1.5",dst_ip:"192.168.1.1",protocol:"ICMP",src_port:null,dst_port:null,flags:null,orig_len:84},
  {ts:0.400,src_ip:"172.16.0.99",dst_ip:"192.168.1.10",protocol:"TCP",src_port:80,dst_port:52800,flags:"PSH+ACK",orig_len:5842},
  {ts:0.500,src_ip:"192.168.1.10",dst_ip:"1.1.1.1",protocol:"UDP",src_port:55000,dst_port:53,flags:null,orig_len:60},
  {ts:0.900,src_ip:"192.168.1.10",dst_ip:"142.250.80.46",protocol:"TCP",src_port:52341,dst_port:443,flags:"FIN+ACK",orig_len:66},
];

/* ─────────────────────────────────────────────────────────
   DESIGN TOKENS
───────────────────────────────────────────────────────── */
const T={bg:"#f7f7f5",surface:"#ffffff",border:"#e3e3de",border2:"#efefeb",text:"#18181b",muted:"#6b7280",faint:"#a3a3a3",accent:"#2563eb",green:"#16a34a",red:"#dc2626",orange:"#d97706",yellow:"#ca8a04"};
const SEV={critical:T.red,high:T.orange,medium:T.yellow,low:T.green};
const PCOL={TCP:T.accent,UDP:T.green,ICMP:T.orange,ARP:"#9333ea",ICMPv6:"#0891b2",IGMP:"#7c3aed",SCTP:"#0e7490",RAW:T.faint};
const PIE_CLR=[T.accent,T.green,T.orange,"#9333ea","#0891b2",T.faint];

const PROTO_PLAIN={TCP:"reliable connection (like a phone call)",UDP:"fast, no confirmation (like a text message)",ICMP:"network ping / error messages",ARP:"devices finding each other on local network",ICMPv6:"same as ICMP but for newer IPv6 addresses",IGMP:"group/multicast communication"};
const PORT_NAMES={80:"Web (HTTP)",443:"Secure Web (HTTPS)",53:"DNS (domain lookup)",22:"SSH (remote login)",23:"Telnet (old remote login)",21:"FTP (file transfer)",25:"Email (SMTP)",110:"Email (POP3)",143:"Email (IMAP)",3389:"Remote Desktop",445:"Windows file sharing",8080:"Web (alternate)",4444:"Hacker tool port",1337:"Hacker tool port",31337:"Hacker tool port"};
function portName(port){return port!=null?(PORT_NAMES[port]?`${port} — ${PORT_NAMES[port]}`:String(port)):"—";}
const FLAG_PLAIN={"SYN":"Opening a connection","ACK":"Acknowledging received data","FIN":"Closing a connection","RST":"Force-closing a connection","PSH":"Sending data","SYN+ACK":"Accepting a connection","FIN+ACK":"Finishing a connection","PSH+ACK":"Sending & confirming data","RST+ACK":"Rejecting a connection"};
function flagPlain(flags){return flags?(FLAG_PLAIN[flags]||flags):null;}

/* ─────────────────────────────────────────────────────────
   SMALL COMPONENTS
───────────────────────────────────────────────────────── */
function Badge({children,color=T.accent}){
  return <span style={{display:"inline-block",padding:"1px 7px",borderRadius:3,fontSize:10,fontWeight:600,letterSpacing:0.2,background:`${color}1a`,color,border:`1px solid ${color}33`,fontFamily:"'DM Mono',monospace"}}>{children}</span>;
}

function Tip({text}){
  const[show,setShow]=useState(false);
  return(
    <span style={{position:"relative",display:"inline-block"}}>
      <span onMouseEnter={()=>setShow(true)} onMouseLeave={()=>setShow(false)}
        style={{cursor:"help",color:T.faint,fontSize:10,marginLeft:4,border:`1px solid ${T.border}`,borderRadius:"50%",width:13,height:13,display:"inline-flex",alignItems:"center",justifyContent:"center"}}>?</span>
      {show&&<div style={{position:"absolute",bottom:"calc(100% + 6px)",left:"50%",transform:"translateX(-50%)",background:T.text,color:"#fff",fontSize:11,lineHeight:1.5,borderRadius:5,padding:"7px 10px",zIndex:200,maxWidth:220,whiteSpace:"normal",boxShadow:"0 4px 12px rgba(0,0,0,0.18)"}}>{text}</div>}
    </span>
  );
}

function StatBox({label,value,help,color}){
  return(
    <div style={{padding:"16px 18px",background:T.surface,border:`1px solid ${T.border}`,borderRadius:6}}>
      <div style={{fontSize:22,fontWeight:700,letterSpacing:-0.5,color:color||T.text,fontFamily:"'DM Mono',monospace"}}>{value}</div>
      <div style={{fontSize:11,color:T.muted,marginTop:3,display:"flex",alignItems:"center"}}>{label}{help&&<Tip text={help}/>}</div>
    </div>
  );
}

function SectionHeader({title,subtitle}){
  return(
    <div style={{marginBottom:20}}>
      <div style={{fontSize:15,fontWeight:600,color:T.text}}>{title}</div>
      {subtitle&&<div style={{fontSize:12,color:T.muted,marginTop:4,lineHeight:1.6}}>{subtitle}</div>}
    </div>
  );
}

const TTip=({active,payload,label})=>{
  if(!active||!payload?.length) return null;
  return(
    <div style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:5,padding:"8px 12px",fontSize:11,color:T.text,boxShadow:"0 2px 8px rgba(0,0,0,0.08)"}}>
      <div style={{color:T.muted,marginBottom:3}}>{label}</div>
      {payload.map((p,i)=><div key={i} style={{color:p.color||T.text}}>{p.name}: <b>{typeof p.value==="number"?p.value.toLocaleString():p.value}</b></div>)}
    </div>
  );
};

function Detail({label,value,sub,highlight}){
  return(
    <div style={{marginBottom:12,paddingBottom:12,borderBottom:`1px solid ${T.border2}`}}>
      <div style={{fontSize:9,color:T.faint,textTransform:"uppercase",letterSpacing:0.6,marginBottom:3}}>{label}</div>
      <div style={{fontSize:12,fontWeight:highlight?600:400,color:highlight?T.text:"#374151"}}>{value}</div>
      {sub&&<div style={{fontSize:11,color:T.muted,marginTop:2}}>{sub}</div>}
    </div>
  );
}

/* ─────────────────────────────────────────────────────────
   ANIMATED TAB CONTENT WRAPPER
───────────────────────────────────────────────────────── */
function AnimatedTab({children, animKey}){
  const ref=useRef();
  useEffect(()=>{
    const el=ref.current; if(!el) return;
    el.style.animation="none";
    void el.offsetHeight; // force reflow
    el.style.animation="tabSlideIn 0.28s cubic-bezier(0.4,0,0.2,1) forwards";
  },[animKey]);
  return <div ref={ref} style={{willChange:"transform,opacity"}}>{children}</div>;
}

/* ─────────────────────────────────────────────────────────
   ANIMATED PAGE TABLE WRAPPER
───────────────────────────────────────────────────────── */
function AnimatedPage({children, pageKey, direction}){
  const ref=useRef();
  useEffect(()=>{
    const el=ref.current; if(!el) return;
    el.style.animation="none";
    void el.offsetHeight;
    const anim=direction==="forward"?"pageSlideLeft":"pageSlideRight";
    el.style.animation=`${anim} 0.22s cubic-bezier(0.4,0,0.2,1) forwards`;
  },[pageKey]);
  return <div ref={ref} style={{willChange:"transform,opacity"}}>{children}</div>;
}

/* ─────────────────────────────────────────────────────────
   SLIDE-OUT DETAIL DRAWER
───────────────────────────────────────────────────────── */
function DetailDrawer({selected,anomalies,onClose}){
  const drawerRef=useRef();
  const prevSelected=useRef(null);

  useEffect(()=>{
    const el=drawerRef.current; if(!el) return;
    if(selected){
      // Slide in from right
      el.style.transition="none";
      if(!prevSelected.current){
        el.style.transform="translateX(100%)";
        el.style.opacity="0";
        void el.offsetHeight;
      }
      el.style.transition="transform 0.32s cubic-bezier(0.4,0,0.2,1), opacity 0.32s cubic-bezier(0.4,0,0.2,1)";
      el.style.transform="translateX(0)";
      el.style.opacity="1";
    } else {
      // Slide out to right
      el.style.transition="transform 0.26s cubic-bezier(0.4,0,0.8,1), opacity 0.26s cubic-bezier(0.4,0,0.8,1)";
      el.style.transform="translateX(100%)";
      el.style.opacity="0";
    }
    prevSelected.current=selected;
  },[selected]);

  // Content crossfade when switching between packets
  const contentRef=useRef();
  const prevIdx=useRef(null);
  useEffect(()=>{
    if(!selected) return;
    const el=contentRef.current; if(!el) return;
    if(prevIdx.current!==null&&prevIdx.current!==selected._idx){
      el.style.animation="none";
      void el.offsetHeight;
      el.style.animation="contentFade 0.18s ease forwards";
    }
    prevIdx.current=selected._idx;
  },[selected]);

  const anom=selected?anomalies.find(a=>a._idx===selected._idx):null;

  return(
    <div ref={drawerRef}
      style={{
        position:"fixed",top:52,right:0,bottom:0,width:340,
        background:T.surface,borderLeft:`1px solid ${T.border}`,
        boxShadow:"-8px 0 32px rgba(0,0,0,0.06)",
        transform:"translateX(100%)",opacity:0,
        zIndex:50,display:"flex",flexDirection:"column",
        overflow:"hidden",
      }}
    >
      {/* Header */}
      <div style={{padding:"14px 18px",borderBottom:`1px solid ${T.border}`,display:"flex",alignItems:"center",justifyContent:"space-between",flexShrink:0}}>
        <div>
          <div style={{fontSize:12,fontWeight:600,color:T.text}}>Packet #{selected?selected._idx+1:"—"} details</div>
          <div style={{fontSize:10,color:T.faint,marginTop:1}}>Click another row to switch</div>
        </div>
        <button onClick={onClose}
          style={{width:28,height:28,borderRadius:4,border:`1px solid ${T.border}`,background:"none",cursor:"pointer",color:T.muted,fontSize:14,display:"flex",alignItems:"center",justifyContent:"center",transition:"background 0.15s"}}
          onMouseEnter={e=>e.target.style.background=T.bg}
          onMouseLeave={e=>e.target.style.background="none"}
        >✕</button>
      </div>

      {/* Scrollable content */}
      <div ref={contentRef} style={{flex:1,overflowY:"auto",padding:"16px 18px"}}>
        {selected&&(
          <>
            <Detail label="What happened?" highlight value={
              flagPlain(selected.flags)
                ? `${flagPlain(selected.flags)}`
                : selected.protocol==="ARP"?"Device asking for someone's location on the local network"
                : selected.protocol==="ICMP"?"A ping or network error message"
                : "Data was transferred"
            } sub={selected.flags?`TCP flag: ${selected.flags}`:null}/>

            <Detail label="Sender (From)" value={selected.src_ip||"Unknown"} sub={selected.src_mac?`Hardware address: ${selected.src_mac}`:null}/>
            <Detail label="Receiver (To)" value={selected.dst_ip||"Unknown"} sub={selected.dst_mac?`Hardware address: ${selected.dst_mac}`:null}/>

            <Detail label="Traffic type" value={selected.protocol||"Unknown"} sub={PROTO_PLAIN[selected.protocol]?`Protocol: ${PROTO_PLAIN[selected.protocol]}`:null}/>

            {selected.dst_port!=null&&<Detail label="Destination service (port)" value={portName(selected.dst_port)} sub="The service or app that received this packet"/>}
            {selected.src_port!=null&&<Detail label="Sender port" value={String(selected.src_port)} sub="The port the sender used"/>}

            <Detail label="Packet size" value={`${(selected.orig_len||0).toLocaleString()} bytes`} sub={`About ${((selected.orig_len||0)/1024).toFixed(2)} KB`}/>
            <Detail label="Time in capture" value={`${(selected.ts||0).toFixed(6)} seconds`} sub="How far into the recording this appeared"/>
            {selected.ttl!=null&&<Detail label="Hops remaining (TTL)" value={String(selected.ttl)} sub="How many more network routers this packet could pass through before being dropped"/>}
            {selected.payload_len!=null&&<Detail label="Data carried" value={`${selected.payload_len.toLocaleString()} bytes`} sub="The actual content inside this packet (after removing headers)"/>}

            {/* Suspicion verdict */}
            <div style={{marginTop:4}}>
              {anom?(
                <div style={{padding:"12px 14px",background:`${SEV[anom.severity]}0e`,border:`1px solid ${SEV[anom.severity]}35`,borderRadius:6}}>
                  <div style={{fontSize:11,fontWeight:600,color:SEV[anom.severity],marginBottom:8,display:"flex",alignItems:"center",gap:6}}>
                    <span>⚠</span> Flagged as <Badge color={SEV[anom.severity]}>{anom.severity}</Badge>
                  </div>
                  {anom.reasons.map((r,i)=>(
                    <div key={i} style={{fontSize:11,color:T.text,marginBottom:5,paddingLeft:8,borderLeft:`2px solid ${SEV[anom.severity]}50`,lineHeight:1.5}}>
                      {r}
                    </div>
                  ))}
                  <div style={{marginTop:10,fontSize:10,color:T.muted,lineHeight:1.6}}>
                    Risk score: <b style={{color:SEV[anom.severity]}}>{anom.score.toFixed(2)}</b> / 1.00
                  </div>
                </div>
              ):(
                <div style={{padding:"10px 14px",background:`${T.green}0e`,border:`1px solid ${T.green}30`,borderRadius:6,fontSize:11,color:T.green,display:"flex",alignItems:"center",gap:6}}>
                  <span>✓</span> Nothing suspicious about this packet
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────
   APP
───────────────────────────────────────────────────────── */
export default function App(){
  const[packets,setPackets]=useState(null);
  const[fileName,setFileName]=useState(null);
  const[parsing,setParsing]=useState(false);
  const[error,setError]=useState(null);
  const[tab,setTab]=useState("overview");
  const[drag,setDrag]=useState(false);
  const[filter,setFilter]=useState("");
  const[page,setPage]=useState(0);
  const[pageDir,setPageDir]=useState("forward");
  const[selected,setSelected]=useState(null);
  const[drawerOpen,setDrawerOpen]=useState(false);
  const PAGE_SIZE=50;
  const fileRef=useRef();

  /* ── File handling ── */
  const handleFile=useCallback((file)=>{
    if(!file) return;
    setError(null);setParsing(true);setPackets(null);setPage(0);setFilter("");setSelected(null);setDrawerOpen(false);
    setFileName(file.name);
    const reader=new FileReader();
    reader.onload=(e)=>{
      try{
        const pkts=parseFile(e.target.result);
        if(!pkts||!pkts.length){setError("Could not read file. Make sure it is a Wireshark .pcap or .pcapng file.");setParsing(false);return;}
        setPackets(pkts);setTab("overview");
      }catch(err){setError("Error reading file: "+err.message);}
      setParsing(false);
    };
    reader.readAsArrayBuffer(file);
  },[]);

  const onDrop=useCallback((e)=>{e.preventDefault();setDrag(false);handleFile(e.dataTransfer.files[0]);},[handleFile]);
  const loadDemo=()=>{setPackets(DEMO_PKTS);setFileName("demo_capture.pcap");setTab("overview");setError(null);setFilter("");setPage(0);setSelected(null);setDrawerOpen(false);};
  const reset=()=>{setPackets(null);setFileName(null);setError(null);setFilter("");setSelected(null);setDrawerOpen(false);};

  const openDrawer=(pkt)=>{setSelected(pkt);setDrawerOpen(true);};
  const closeDrawer=()=>{setDrawerOpen(false);setTimeout(()=>setSelected(null),320);};

  const switchTab=(id)=>{setTab(id);setSelected(null);setDrawerOpen(false);setPage(0);};

  const goPage=(dir)=>{
    setPageDir(dir);
    setPage(p=>dir==="forward"?p+1:p-1);
    setSelected(null);setDrawerOpen(false);
  };

  /* ── Derived ── */
  const pkts=packets||[];
  const stats=computeStats(pkts);
  const anomalies=detectAnomalies(pkts);
  const protoDist=Object.entries(pkts.reduce((a,p)=>{a[p.protocol||"?"]=(a[p.protocol||"?"]||0)+1;return a;},{})).map(([name,value])=>({name,value})).sort((a,b)=>b.value-a.value);
  const ipDist=Object.entries(pkts.reduce((a,p)=>{if(p.src_ip)a[p.src_ip]=(a[p.src_ip]||0)+1;return a;},{})).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([ip,count])=>({ip,count}));
  const filteredPkts=pkts.filter(p=>matchesFilter(p,filter));
  const pagePkts=filteredPkts.slice(page*PAGE_SIZE,(page+1)*PAGE_SIZE);
  const totalPages=Math.ceil(filteredPkts.length/PAGE_SIZE);
  const timeSeries=(()=>{
    if(!pkts.length) return[];
    const min=pkts[0].ts||0;const buckets={};
    pkts.forEach(p=>{const b=(Math.floor(((p.ts||0)-min)*5)/5).toFixed(1);if(!buckets[b])buckets[b]={t:b,packets:0,bytes:0};buckets[b].packets++;buckets[b].bytes+=p.orig_len||0;});
    return Object.values(buckets).sort((a,b)=>parseFloat(a.t)-parseFloat(b.t));
  })();
  const uniqueIPs=new Set([...pkts.map(p=>p.src_ip),...pkts.map(p=>p.dst_ip)].filter(Boolean)).size;
  const sevCounts=anomalies.reduce((a,x)=>{a[x.severity]=(a[x.severity]||0)+1;return a;},{});
  const highRisk=(sevCounts.critical||0)+(sevCounts.high||0);

  const TABS=[
    {id:"overview",label:"Summary"},
    {id:"packets",label:`All Packets (${pkts.length.toLocaleString()})`},
    {id:"anomalies",label:`⚠ Suspicious (${anomalies.length})`},
    {id:"charts",label:"Charts"},
  ];

  return(
    <div style={{minHeight:"100vh",background:T.bg,fontFamily:"'DM Sans','Helvetica Neue',sans-serif",color:T.text}}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700&display=swap');
        *{box-sizing:border-box;margin:0;padding:0}
        ::-webkit-scrollbar{width:5px;height:5px}
        ::-webkit-scrollbar-track{background:transparent}
        ::-webkit-scrollbar-thumb{background:${T.border};border-radius:3px}
        button:focus-visible,input:focus{outline:2px solid ${T.accent};outline-offset:2px}

        @keyframes tabSlideIn{
          from{opacity:0;transform:translateY(10px)}
          to{opacity:1;transform:translateY(0)}
        }
        @keyframes pageSlideLeft{
          from{opacity:0;transform:translateX(40px)}
          to{opacity:1;transform:translateX(0)}
        }
        @keyframes pageSlideRight{
          from{opacity:0;transform:translateX(-40px)}
          to{opacity:1;transform:translateX(0)}
        }
        @keyframes contentFade{
          from{opacity:0;transform:translateY(6px)}
          to{opacity:1;transform:translateY(0)}
        }

        .prow{transition:background 0.12s;}
        .prow:hover{background:#f0f0ec !important;cursor:pointer}
        .prow.selected{background:${T.accent}0d !important}
        .tab-btn{transition:color 0.15s;}
        .close-btn:hover{background:${T.bg} !important}
      `}</style>

      {/* ── HEADER ── */}
      <div style={{background:T.surface,borderBottom:`1px solid ${T.border}`,padding:"0 32px",position:"sticky",top:0,zIndex:30}}>
        <div style={{maxWidth:1120,margin:"0 auto",display:"flex",alignItems:"center",justifyContent:"space-between",height:52}}>
          <div style={{display:"flex",alignItems:"center",gap:8}}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={T.accent} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
            <span style={{fontWeight:700,fontSize:14}}>Network Traffic Inspector</span>
            <span style={{fontSize:11,color:T.faint,marginLeft:2}}>Wireshark file analyser · beginner friendly</span>
          </div>
          {packets&&(
            <div style={{display:"flex",alignItems:"center",gap:10}}>
              <span style={{fontSize:11,color:T.muted,fontFamily:"'DM Mono',monospace"}}>{fileName}</span>
              <button onClick={reset} style={{fontSize:11,color:T.muted,background:"none",border:`1px solid ${T.border}`,borderRadius:4,padding:"4px 10px",cursor:"pointer"}}>× New file</button>
            </div>
          )}
        </div>
      </div>

      {/* ── SLIDE-OUT DRAWER ── */}
      <DetailDrawer selected={selected} anomalies={anomalies} onClose={closeDrawer}/>

      {/* ── MAIN AREA (shifts left when drawer opens) ── */}
      <div style={{
        maxWidth:1120,margin:"0 auto",padding:"28px 32px",
        transition:"padding-right 0.32s cubic-bezier(0.4,0,0.2,1)",
        paddingRight: drawerOpen ? "372px" : "32px",
      }}>

        {/* UPLOAD */}
        {!packets&&!parsing&&(
          <AnimatedTab animKey="upload">
            <div style={{maxWidth:600}}>
              <h1 style={{fontSize:24,fontWeight:700,letterSpacing:-0.6,marginBottom:8}}>Inspect your network capture</h1>
              <p style={{color:T.muted,fontSize:13,lineHeight:1.7,marginBottom:8}}>
                This tool reads a file recorded by <b>Wireshark</b> and shows you what was happening on your network in plain English — who was talking to whom, what kind of traffic it was, and whether anything looks suspicious.
              </p>
              <p style={{color:T.muted,fontSize:13,lineHeight:1.7,marginBottom:24}}>
                <b>Your file never leaves your computer.</b> Everything is read directly in your browser.
              </p>
              {error&&<div style={{padding:"10px 14px",background:"#dc262612",border:"1px solid #dc262635",borderRadius:5,color:T.red,fontSize:13,marginBottom:16}}>{error}</div>}
              <div
                onDrop={onDrop} onDragOver={e=>{e.preventDefault();setDrag(true);}} onDragLeave={()=>setDrag(false)}
                onClick={()=>fileRef.current?.click()}
                style={{border:`2px dashed ${drag?T.accent:T.border}`,borderRadius:8,padding:"52px 40px",textAlign:"center",background:drag?`${T.accent}06`:T.surface,cursor:"pointer",transition:"border-color 0.15s,background 0.15s"}}
              >
                <input ref={fileRef} type="file" accept=".pcap,.pcapng,.cap" style={{display:"none"}} onChange={e=>handleFile(e.target.files[0])}/>
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke={drag?T.accent:T.faint} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{margin:"0 auto 14px",display:"block"}}>
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
                </svg>
                <div style={{fontSize:14,fontWeight:600,color:drag?T.accent:T.text,marginBottom:5}}>{drag?"Release to open":"Drop your Wireshark file here"}</div>
                <div style={{fontSize:12,color:T.faint}}>or click to browse · .pcap · .pcapng · .cap</div>
              </div>
              <div style={{textAlign:"center",marginTop:16}}>
                <span style={{fontSize:12,color:T.faint}}>Don't have a file? </span>
                <button onClick={loadDemo} style={{fontSize:12,color:T.accent,background:"none",border:"none",cursor:"pointer",textDecoration:"underline",textUnderlineOffset:2}}>Load a demo capture</button>
              </div>
              <div style={{marginTop:28,padding:"16px 18px",background:T.surface,border:`1px solid ${T.border}`,borderRadius:6}}>
                <div style={{fontSize:11,fontWeight:600,marginBottom:10,color:T.muted,textTransform:"uppercase",letterSpacing:0.5}}>Quick glossary</div>
                {[["📦 Packet","A small chunk of data travelling across a network. Like an envelope in the mail."],["🏠 IP Address","A unique address for each device, like a home address. Tells traffic where to go."],["🚪 Port","A numbered door on a device. Different apps use different doors (e.g. port 443 = secure web)."],["🔗 Protocol","The language two devices agree to speak (TCP, UDP, ICMP…)."],["⚠ Anomaly","Something that looks unusual compared to the rest of the traffic."]].map(([term,def])=>(
                  <div key={term} style={{display:"flex",gap:10,marginBottom:8}}>
                    <div style={{fontSize:12,fontWeight:600,minWidth:110,color:T.text}}>{term}</div>
                    <div style={{fontSize:12,color:T.muted,lineHeight:1.5}}>{def}</div>
                  </div>
                ))}
              </div>
            </div>
          </AnimatedTab>
        )}

        {parsing&&(
          <div style={{display:"flex",alignItems:"center",gap:12}}>
            <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
            <div style={{width:16,height:16,border:`2px solid ${T.border}`,borderTopColor:T.accent,borderRadius:"50%",animation:"spin 0.7s linear infinite"}}/>
            <span style={{fontSize:13,color:T.muted}}>Reading {fileName}…</span>
          </div>
        )}

        {packets&&(
          <>
            {/* Tabs */}
            <div style={{display:"flex",borderBottom:`1px solid ${T.border}`,marginBottom:24}}>
              {TABS.map(({id,label})=>(
                <button key={id} className="tab-btn" onClick={()=>switchTab(id)} style={{padding:"9px 18px",fontSize:13,fontWeight:tab===id?600:400,color:tab===id?T.text:T.muted,background:"none",border:"none",borderBottom:`2px solid ${tab===id?T.text:"transparent"}`,marginBottom:-1,cursor:"pointer"}}>
                  {label}
                </button>
              ))}
            </div>

            {/* ══ OVERVIEW ══ */}
            {tab==="overview"&&(
              <AnimatedTab animKey="overview">
                <SectionHeader title="What's in this capture?" subtitle="Here's a plain-English summary of everything recorded in your Wireshark file."/>
                <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:8,marginBottom:12}}>
                  <StatBox label="Total packets recorded" value={pkts.length.toLocaleString()} help="A packet is a small chunk of data sent over the network. This is the total number captured."/>
                  <StatBox label="Devices involved" value={uniqueIPs.toLocaleString()} help="Unique IP addresses seen as either sender or receiver."/>
                  <StatBox label="Suspicious events" value={anomalies.length} color={anomalies.length>0?T.orange:T.green} help="Packets that looked unusual based on size, behaviour, or destination port."/>
                  <StatBox label="High-risk events" value={highRisk} color={highRisk>0?T.red:T.green} help="The most serious findings — potential port scans, flood attacks, or connections to known hacker ports."/>
                </div>
                <div style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:6,padding:"16px 18px",marginBottom:16}}>
                  <div style={{fontSize:12,fontWeight:600,marginBottom:4}}>Packet sizes <Tip text="How big were the packets? Measured in bytes. 1 KB = 1,024 bytes."/></div>
                  <div style={{fontSize:12,color:T.muted,marginBottom:12,lineHeight:1.6}}>
                    Most packets were around <b>{stats.median} bytes</b>. The average was <b>{stats.mean} bytes</b>. The biggest single packet was <b>{stats.max} bytes</b>. 95% of packets were smaller than <b>{stats.p95} bytes</b>.
                  </div>
                  <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:8}}>
                    {[["Average",stats.mean+"B","Mean packet size"],["Middle value",stats.median+"B","Half were above, half below"],["Variation",stats.std+"B","How spread out the sizes are"],["95th percentile",stats.p95+"B","95% of packets are smaller than this"],["Largest",stats.max+"B","The biggest packet in the file"]].map(([k,v,h])=>(
                      <div key={k} style={{padding:"10px 12px",background:T.bg,border:`1px solid ${T.border}`,borderRadius:5}}>
                        <div style={{fontSize:14,fontWeight:600,fontFamily:"'DM Mono',monospace",color:T.text}}>{v}</div>
                        <div style={{fontSize:10,color:T.faint,marginTop:2}}>{k}<Tip text={h}/></div>
                      </div>
                    ))}
                  </div>
                </div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
                  <div style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:6,padding:"16px 18px"}}>
                    <div style={{fontSize:12,fontWeight:600,marginBottom:4}}>Traffic types <Tip text="What kind of communication was happening?"/></div>
                    <div style={{fontSize:12,color:T.muted,marginBottom:12,lineHeight:1.5}}>Different protocols are like different languages devices speak to each other.</div>
                    {protoDist.map(p=>(
                      <div key={p.name} style={{marginBottom:10}}>
                        <div style={{display:"flex",justifyContent:"space-between",marginBottom:3}}>
                          <div style={{display:"flex",alignItems:"center",gap:6}}>
                            <Badge color={PCOL[p.name]||T.faint}>{p.name}</Badge>
                            <span style={{fontSize:11,color:T.muted}}>{PROTO_PLAIN[p.name]||""}</span>
                          </div>
                          <span style={{fontSize:11,color:T.muted,fontFamily:"'DM Mono',monospace"}}>{p.value} ({(p.value/pkts.length*100).toFixed(0)}%)</span>
                        </div>
                        <div style={{height:3,background:T.border2,borderRadius:2}}>
                          <div style={{width:`${(p.value/pkts.length*100)}%`,height:"100%",background:PCOL[p.name]||T.faint,borderRadius:2,transition:"width 0.6s ease"}}/>
                        </div>
                      </div>
                    ))}
                  </div>
                  <div style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:6,padding:"16px 18px"}}>
                    <div style={{fontSize:12,fontWeight:600,marginBottom:4}}>Most active senders <Tip text="Which IP addresses sent the most packets?"/></div>
                    <div style={{fontSize:12,color:T.muted,marginBottom:12,lineHeight:1.5}}>An IP address is like a home address — it identifies each device on the network.</div>
                    {ipDist.map(({ip,count})=>(
                      <div key={ip} style={{marginBottom:10}}>
                        <div style={{display:"flex",justifyContent:"space-between",marginBottom:3}}>
                          <span style={{fontSize:11,fontFamily:"'DM Mono',monospace",color:T.text}}>{ip}</span>
                          <span style={{fontSize:11,color:T.muted}}>{count} packets</span>
                        </div>
                        <div style={{height:3,background:T.border2,borderRadius:2}}>
                          <div style={{width:`${(count/ipDist[0].count*100)}%`,height:"100%",background:`${T.accent}70`,borderRadius:2,transition:"width 0.6s ease"}}/>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </AnimatedTab>
            )}

            {/* ══ PACKETS ══ */}
            {tab==="packets"&&(
              <AnimatedTab animKey="packets">
                <SectionHeader title="All recorded packets" subtitle="Every packet captured in the file. Click any row to open a plain-English explanation on the right. Use the search box to filter by IP address, protocol type, or port number."/>
                <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:14}}>
                  <div style={{position:"relative",flex:1}}>
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={T.faint} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{position:"absolute",left:10,top:"50%",transform:"translateY(-50%)"}}>
                      <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                    </svg>
                    <input value={filter} onChange={e=>{setFilter(e.target.value);setPage(0);setSelected(null);setDrawerOpen(false);}}
                      placeholder="Search by IP address, protocol (TCP, UDP…), or port number…"
                      style={{width:"100%",padding:"8px 12px 8px 32px",fontSize:12,fontFamily:"'DM Mono',monospace",background:T.surface,border:`1px solid ${T.border}`,borderRadius:5,color:T.text,transition:"border-color 0.15s"}}
                      onFocus={e=>e.target.style.borderColor=T.accent} onBlur={e=>e.target.style.borderColor=T.border}
                    />
                  </div>
                  {filter&&<button onClick={()=>{setFilter("");setPage(0);setSelected(null);setDrawerOpen(false);}} style={{fontSize:12,color:T.muted,background:T.surface,border:`1px solid ${T.border}`,borderRadius:4,padding:"8px 12px",cursor:"pointer",whiteSpace:"nowrap"}}>Clear</button>}
                  <span style={{fontSize:11,color:T.faint,whiteSpace:"nowrap"}}>
                    {filter?`${filteredPkts.length.toLocaleString()} of ${pkts.length.toLocaleString()}`:`${pkts.length.toLocaleString()} total`}
                  </span>
                </div>

                {filteredPkts.length===0?(
                  <div style={{padding:"24px",textAlign:"center",color:T.muted,fontSize:13,background:T.surface,border:`1px solid ${T.border}`,borderRadius:6}}>
                    No packets match <b>"{filter}"</b>. Try an IP like <code>192.168</code>, a protocol like <code>TCP</code>, or a port like <code>443</code>.
                  </div>
                ):(
                  <>
                    <AnimatedPage pageKey={page} direction={pageDir}>
                      <div style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:6,overflow:"hidden"}}>
                        <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
                          <thead>
                            <tr style={{background:T.bg}}>
                              <th style={TH}>#</th>
                              <th style={TH}>Time <Tip text="Seconds since the start of the capture"/></th>
                              <th style={TH}>From <Tip text="The device that sent this packet"/></th>
                              <th style={TH}>To <Tip text="The device that received this packet"/></th>
                              <th style={TH}>Type <Tip text="The protocol — the language used"/></th>
                              <th style={TH}>Service <Tip text="Port number — identifies which app or service (e.g. 443 = secure web)"/></th>
                              <th style={TH}>Action <Tip text="What was happening (TCP connections only)"/></th>
                              <th style={{...TH,textAlign:"right"}}>Size <Tip text="How many bytes this packet contained"/></th>
                            </tr>
                          </thead>
                          <tbody>
                            {pagePkts.map((p,i)=>{
                              const idx=page*PAGE_SIZE+i;
                              const isSel=selected?._idx===idx;
                              return(
                                <tr key={idx} className={`prow${isSel?" selected":""}`}
                                  onClick={()=>{
                                    if(isSel){closeDrawer();}
                                    else{openDrawer({...p,_idx:idx});}
                                  }}
                                  style={{borderBottom:`1px solid ${T.border2}`,background:isSel?`${T.accent}0d`:i%2===0?T.surface:T.bg}}
                                >
                                  <td style={TD}><span style={{color:T.faint,fontFamily:"'DM Mono',monospace",fontSize:10}}>{idx+1}</span></td>
                                  <td style={TD}><span style={{fontFamily:"'DM Mono',monospace",color:T.muted,fontSize:11}}>{(p.ts||0).toFixed(3)}s</span></td>
                                  <td style={TD}><span style={{fontFamily:"'DM Mono',monospace",fontSize:11}}>{p.src_ip||"—"}</span></td>
                                  <td style={TD}><span style={{fontFamily:"'DM Mono',monospace",fontSize:11}}>{p.dst_ip||"—"}</span></td>
                                  <td style={TD}><Badge color={PCOL[p.protocol]||T.faint}>{p.protocol||"?"}</Badge></td>
                                  <td style={TD}><span style={{fontFamily:"'DM Mono',monospace",color:T.muted,fontSize:11}}>{p.dst_port!=null?p.dst_port:"—"}</span></td>
                                  <td style={TD}>{flagPlain(p.flags)?<span style={{fontSize:11,color:T.muted}}>{flagPlain(p.flags)}</span>:<span style={{color:T.border2}}>—</span>}</td>
                                  <td style={{...TD,textAlign:"right"}}><span style={{fontFamily:"'DM Mono',monospace",color:T.muted,fontSize:11}}>{(p.orig_len||0).toLocaleString()}B</span></td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    </AnimatedPage>

                    {/* Pagination */}
                    {totalPages>1&&(
                      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginTop:14}}>
                        <button disabled={page===0} onClick={()=>goPage("back")} style={pgBtn(page===0)}>← Previous</button>
                        <div style={{display:"flex",alignItems:"center",gap:6}}>
                          {Array.from({length:Math.min(totalPages,7)},(_,i)=>{
                            const p=totalPages<=7?i:page<=3?i:page>=totalPages-4?totalPages-7+i:page-3+i;
                            return(
                              <button key={p} onClick={()=>{setPageDir(p>page?"forward":"back");setPage(p);setSelected(null);setDrawerOpen(false);}}
                                style={{width:28,height:28,borderRadius:4,border:`1px solid ${p===page?T.accent:T.border}`,background:p===page?`${T.accent}12`:"none",color:p===page?T.accent:T.muted,fontSize:11,cursor:"pointer",transition:"all 0.15s"}}>
                                {p+1}
                              </button>
                            );
                          })}
                        </div>
                        <button disabled={page===totalPages-1} onClick={()=>goPage("forward")} style={pgBtn(page===totalPages-1)}>Next →</button>
                      </div>
                    )}
                  </>
                )}
              </AnimatedTab>
            )}

            {/* ══ ANOMALIES ══ */}
            {tab==="anomalies"&&(
              <AnimatedTab animKey="anomalies">
                <SectionHeader title="Suspicious activity" subtitle="These packets stood out as unusual. This doesn't automatically mean something bad is happening — but they're worth a closer look."/>
                <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:8,marginBottom:20}}>
                  {["critical","high","medium","low"].map(s=>(
                    <div key={s} style={{padding:"12px 16px",background:T.surface,border:`1px solid ${SEV[s]}40`,borderRadius:5,transition:"transform 0.15s"}} onMouseEnter={e=>e.currentTarget.style.transform="translateY(-1px)"} onMouseLeave={e=>e.currentTarget.style.transform=""}>
                      <div style={{fontSize:18,fontWeight:700,color:SEV[s],fontFamily:"'DM Mono',monospace"}}>{sevCounts[s]||0}</div>
                      <div style={{fontSize:11,color:T.muted,marginTop:2,textTransform:"capitalize"}}>{s} risk</div>
                    </div>
                  ))}
                </div>
                {!anomalies.length?(
                  <div style={{padding:32,textAlign:"center",color:T.muted,fontSize:13,background:T.surface,border:`1px solid ${T.border}`,borderRadius:6}}>
                    ✓ Nothing suspicious found in this capture. The traffic looks normal.
                  </div>
                ):(
                  <div style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:6,overflow:"hidden",marginBottom:20}}>
                    <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
                      <thead>
                        <tr style={{background:T.bg}}>
                          <th style={TH}>Risk level</th>
                          <th style={TH}>Sender <Tip text="The device that sent this suspicious packet"/></th>
                          <th style={TH}>What was found</th>
                          <th style={TH}>Service targeted <Tip text="The destination port and what it is normally used for"/></th>
                          <th style={{...TH,textAlign:"right"}}>Risk score <Tip text="0 = no risk, 1.0 = maximum risk"/></th>
                        </tr>
                      </thead>
                      <tbody>
                        {anomalies.slice(0,80).map((a,i)=>(
                          <tr key={i} style={{borderBottom:`1px solid ${T.border2}`,background:i%2===0?T.surface:T.bg}}>
                            <td style={TD}><Badge color={SEV[a.severity]}>{a.severity}</Badge></td>
                            <td style={{...TD,fontFamily:"'DM Mono',monospace"}}>{a.src_ip}</td>
                            <td style={TD}>{a.reasons.map((r,j)=><div key={j} style={{fontSize:11,color:T.text,marginBottom:j<a.reasons.length-1?3:0}}>• {r}</div>)}</td>
                            <td style={TD}>
                              {a.dst_port!=null
                                ?<><Badge color={PCOL[a.protocol]||T.faint}>{a.protocol}</Badge><span style={{marginLeft:5,fontSize:11,color:T.muted}}>{portName(a.dst_port)}</span></>
                                :<Badge color={PCOL[a.protocol]||T.faint}>{a.protocol}</Badge>}
                            </td>
                            <td style={{...TD,textAlign:"right"}}>
                              <div style={{display:"flex",alignItems:"center",justifyContent:"flex-end",gap:8}}>
                                <div style={{width:48,height:3,background:T.border2,borderRadius:2}}>
                                  <div style={{width:`${a.score*100}%`,height:"100%",background:SEV[a.severity],borderRadius:2}}/>
                                </div>
                                <span style={{fontSize:11,fontFamily:"'DM Mono',monospace",color:T.muted}}>{a.score.toFixed(2)}</span>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                <div style={{fontSize:13,fontWeight:600,marginBottom:10}}>How does this detection work?</div>
                <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:10}}>
                  {[{icon:"📏",name:"Unusual packet size",desc:"We calculate the average packet size across your entire capture. Any packet much larger or smaller than normal (more than 3× the standard deviation away) gets flagged. This can indicate data exfiltration or malformed packets.",color:T.accent},{icon:"🚪",name:"Port scanning",desc:"If one device tries connecting to more than 15 different services on another device in rapid succession, it looks like a port scan — a common first step attackers use to find open doors on a system.",color:"#0891b2"},{icon:"⚡",name:"Suspicious ports & floods",desc:"Some port numbers are almost exclusively used by hacking tools (e.g. 4444, 1337, 31337). We also flag SYN floods — when a device sends tons of connection requests without ever completing them.",color:T.orange}].map(m=>(
                    <div key={m.name} style={{padding:16,background:T.surface,border:`1px solid ${T.border}`,borderRadius:6}}>
                      <div style={{fontSize:18,marginBottom:8}}>{m.icon}</div>
                      <div style={{fontSize:12,fontWeight:600,color:m.color,marginBottom:6}}>{m.name}</div>
                      <div style={{fontSize:12,color:T.muted,lineHeight:1.65}}>{m.desc}</div>
                    </div>
                  ))}
                </div>
              </AnimatedTab>
            )}

            {/* ══ CHARTS ══ */}
            {tab==="charts"&&(
              <AnimatedTab animKey="charts">
                <SectionHeader title="Visual breakdown" subtitle="Charts help you spot patterns at a glance — which devices were busiest, what kind of traffic dominated, and how activity changed over time."/>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
                  <div style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:6,padding:20}}>
                    <div style={{fontSize:12,fontWeight:600,marginBottom:4}}>Traffic types (protocols)</div>
                    <div style={{fontSize:11,color:T.muted,marginBottom:14}}>What kind of communication made up most of the traffic?</div>
                    <ResponsiveContainer width="100%" height={190}>
                      <PieChart>
                        <Pie data={protoDist} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={48} outerRadius={76} paddingAngle={2}>
                          {protoDist.map((_,i)=><Cell key={i} fill={PIE_CLR[i%PIE_CLR.length]}/>)}
                        </Pie>
                        <Tooltip content={<TTip/>}/>
                      </PieChart>
                    </ResponsiveContainer>
                    <div style={{display:"flex",flexWrap:"wrap",gap:"4px 14px",marginTop:8}}>
                      {protoDist.map((p,i)=><div key={p.name} style={{display:"flex",alignItems:"center",gap:5,fontSize:11,color:T.muted}}><div style={{width:8,height:8,borderRadius:2,background:PIE_CLR[i%PIE_CLR.length]}}/>{p.name} ({p.value})</div>)}
                    </div>
                  </div>
                  <div style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:6,padding:20}}>
                    <div style={{fontSize:12,fontWeight:600,marginBottom:4}}>Most active senders</div>
                    <div style={{fontSize:11,color:T.muted,marginBottom:14}}>Which devices sent the most packets during the capture?</div>
                    <ResponsiveContainer width="100%" height={230}>
                      <BarChart data={ipDist} layout="vertical" margin={{top:0,right:12,left:10,bottom:0}}>
                        <XAxis type="number" tick={{fontSize:9,fill:T.faint}} axisLine={false} tickLine={false}/>
                        <YAxis dataKey="ip" type="category" tick={{fontSize:9,fill:T.muted,fontFamily:"'DM Mono',monospace"}} axisLine={false} tickLine={false} width={100}/>
                        <Tooltip content={<TTip/>}/>
                        <Bar dataKey="count" name="Packets sent" fill={T.accent} radius={[0,3,3,0]}/>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                  {timeSeries.length>1&&(
                    <div style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:6,padding:20,gridColumn:"span 2"}}>
                      <div style={{fontSize:12,fontWeight:600,marginBottom:4}}>Traffic over time</div>
                      <div style={{fontSize:11,color:T.muted,marginBottom:14}}>How many packets were recorded at each moment? Spikes can indicate bursts of activity.</div>
                      <ResponsiveContainer width="100%" height={180}>
                        <AreaChart data={timeSeries} margin={{top:0,right:0,left:-20,bottom:0}}>
                          <defs>
                            <linearGradient id="ag" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor={T.accent} stopOpacity={0.12}/>
                              <stop offset="95%" stopColor={T.accent} stopOpacity={0}/>
                            </linearGradient>
                          </defs>
                          <CartesianGrid strokeDasharray="3 3" stroke={T.border2}/>
                          <XAxis dataKey="t" tick={{fontSize:9,fill:T.faint}} tickFormatter={v=>`${v}s`}/>
                          <YAxis tick={{fontSize:9,fill:T.faint}}/>
                          <Tooltip content={<TTip/>}/>
                          <Area type="monotone" dataKey="packets" name="Packets" stroke={T.accent} strokeWidth={1.5} fill="url(#ag)" dot={false}/>
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  )}
                  {anomalies.length>0&&(
                    <div style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:6,padding:20,gridColumn:"span 2"}}>
                      <div style={{fontSize:12,fontWeight:600,marginBottom:4}}>Suspicious activity by risk level</div>
                      <div style={{fontSize:11,color:T.muted,marginBottom:14}}>How many suspicious events fell into each category?</div>
                      {["critical","high","medium","low"].filter(s=>sevCounts[s]).map(sev=>(
                        <div key={sev} style={{display:"flex",alignItems:"center",gap:12,marginBottom:10}}>
                          <div style={{width:72}}><Badge color={SEV[sev]}>{sev}</Badge></div>
                          <div style={{flex:1,height:5,background:T.border2,borderRadius:3}}>
                            <div style={{width:`${(sevCounts[sev]/anomalies.length*100).toFixed(0)}%`,height:"100%",background:SEV[sev],borderRadius:3,transition:"width 0.5s ease"}}/>
                          </div>
                          <span style={{fontSize:11,fontFamily:"'DM Mono',monospace",color:T.muted,width:28,textAlign:"right"}}>{sevCounts[sev]}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </AnimatedTab>
            )}
          </>
        )}

        {/* Footer */}
        <div style={{marginTop:44,paddingTop:14,borderTop:`1px solid ${T.border}`,display:"flex",justifyContent:"space-between",fontSize:11,color:T.faint}}>
          <span>log_parser.py · analysis.py · pipeline.py</span>
          <span>pandas 2.2 · numpy 1.26 · PCAP/PCAPNG binary parser</span>
        </div>
      </div>
    </div>
  );
}

/* ── Style constants ── */
const TH={padding:"7px 12px",textAlign:"left",color:"#a3a3a3",fontWeight:500,fontSize:10,letterSpacing:0.4,textTransform:"uppercase",borderBottom:"1px solid #e3e3de",whiteSpace:"nowrap",fontFamily:"'DM Sans',sans-serif"};
const TD={padding:"6px 12px",verticalAlign:"middle"};
const pgBtn=disabled=>({fontSize:12,padding:"6px 14px",background:"#ffffff",border:"1px solid #e3e3de",borderRadius:4,cursor:disabled?"not-allowed":"pointer",color:disabled?"#a3a3a3":"#18181b",transition:"background 0.15s"});

