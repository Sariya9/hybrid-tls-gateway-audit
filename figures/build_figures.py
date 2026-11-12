#!/usr/bin/env python3
"""Build editable vector figures from retained ICETE observations; no new TLS run."""
import argparse
import hashlib
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, FancyArrowPatch

plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8.2,
                     "pdf.fonttype": 42, "ps.fonttype": 42})
INK = "#24313b"
BLUE = "#215a87"
TEAL = "#246a63"
ORANGE = "#97530a"
RED = "#8d3037"
PALE = "#f1f4f6"


def canvas(height):
    fig, ax = plt.subplots(figsize=(7.16, height))
    fig.subplots_adjust(0, 0, 1, 1)
    ax.set(xlim=(0, 1), ylim=(0, 1))
    ax.axis("off")
    return fig, ax


def box(ax, x, y, w, h, title, body="", edge=INK, fill="white", size=8.3):
    ax.add_patch(Rectangle((x, y), w, h, facecolor=fill, edgecolor=edge, linewidth=1,zorder=2))
    if body:
        ax.text(x+w/2, y+h*.73, title, ha="center", va="center",
                color=edge, fontsize=size, fontweight="bold",zorder=3)
        ax.text(x+w/2, y+h*.30, body, ha="center", va="center",
                color=INK, fontsize=size-.4, linespacing=1.2,zorder=3)
    else:
        ax.text(x+w/2, y+h/2, title, ha="center", va="center",
                color=edge, fontsize=size, linespacing=1.2,zorder=3)


def arrow(ax, a, b, label="", color=INK, both=False, dy=.025, dashed=False, size=7.7):
    ax.add_patch(FancyArrowPatch(a, b, arrowstyle="<->" if both else "-|>",
                                mutation_scale=8, linewidth=.9, color=color,
                                linestyle="--" if dashed else "-"))
    if label:
        ax.text((a[0]+b[0])/2, (a[1]+b[1])/2+dy, label,
                ha="center", va="bottom", color=color, fontsize=size,
                linespacing=1.1)


def route(ax, points, color=INK, dashed=False):
    for a, b in zip(points[:-2], points[1:-1]):
        ax.plot([a[0], b[0]], [a[1], b[1]], color=color, linewidth=.9,
                linestyle="--" if dashed else "-")
    arrow(ax, points[-2], points[-1], color=color, dashed=dashed)


def framework():
    fig, ax = canvas(2.65)
    box(ax,.32,.80,.36,.17,"Operator declaration D","Required legs: none / F / B / both",BLUE,PALE)
    box(ax,.02,.42,.18,.25,"Client C","Offer list\nVerify proxy.test",BLUE)
    box(ax,.38,.36,.24,.34,"Terminating gateway P",
        "Front TLS | backend TLS\nPlaintext; optional guard",ORANGE,size=8)
    box(ax,.80,.42,.18,.25,"Origin S","Acceptance list\nOrigin certificate",TEAL)
    arrow(ax,(.20,.55),(.38,.55),"F: client-facing TLS",BLUE,both=True,dy=.04)
    arrow(ax,(.62,.55),(.80,.55),"B: origin-facing TLS",TEAL,both=True,dy=.04)
    ax.text(.29,.43,"C verifies P",ha="center",fontsize=7.7,color=BLUE)
    ax.text(.71,.43,"P verifies S",ha="center",fontsize=7.7,color=TEAL)
    arrow(ax,(.50,.80),(.50,.70),"",BLUE)
    box(ax,.30,.02,.40,.18,"Independent trace checker",
        "Authentication + groups + accepted writes",INK,PALE)
    for x, y in ((.11,.42),(.50,.36),(.89,.42)):
        route(ax,[(x,y),(x,.26),(.50,.26),(.50,.20)])
    ax.text(.72,.28,"Ordered events",fontsize=7.4,color=INK,ha="center")
    route(ax,[(.68,.88),(.98,.88),(.98,.10),(.70,.10)],BLUE,True)
    ax.text(.835,.79,"D always checked",ha="center",fontsize=7.4,color=BLUE)
    ax.text(.02,.08,"Separate local CAs;\nclassical certificate authentication",
            fontsize=7.4,va="center",color=INK)
    return fig


def methodology():
    fig, ax = canvas(2.65)
    w=.27
    box(ax,.025,.65,w,.25,"1  Freeze the test contract",
        "Group lists, D, guard toggle\n16 predicted observations",BLUE,PALE)
    box(ax,.365,.65,w,.25,"2  Create a fresh run",
        "Compile native probe\nNew local CAs and payload",INK)
    box(ax,.705,.65,w,.25,"3  Execute each case",
        "Client + gateway + origin\nLoopback; bounded I/O",INK)
    arrow(ax,(.295,.775),(.365,.775),"config",size=7,dy=.025)
    arrow(ax,(.635,.775),(.705,.775))
    box(ax,.705,.25,w,.25,"4  Retain observations",
        "Offers, handshakes, byte events\nAlerts and process exits",INK)
    box(ax,.365,.25,w,.25,"5  Evaluate route policy",
        "Auth + groups + release + D\nConforming delivery / refusal\nor policy violation",TEAL,PALE,size=8)
    box(ax,.025,.25,w,.25,"6  Check the prediction",
        "Expected versus observed\nRetain evidence and tables",INK)
    arrow(ax,(.84,.65),(.84,.50))
    arrow(ax,(.705,.375),(.635,.375))
    arrow(ax,(.365,.375),(.295,.375))
    arrow(ax,(.16,.65),(.16,.50),"predictions",BLUE,dy=0,size=7.3,dashed=True)
    route(ax,[(.26,.65),(.26,.55),(.50,.55),(.50,.50)],BLUE,True)
    ax.text(.36,.555,"D",color=BLUE,fontsize=8)
    box(ax,.025,.015,.95,.13,
        "Separate extracted execution repeats steps 2–6 on the same host and OpenSSL.",
        edge=TEAL,fill=PALE,size=8)
    return fig


def sequence(cases):
    for ident in ("M05","M06"):
        c=cases[ident]
        streams={name:p["events"] for name,p in c["processes"].items()}
        origin=streams["origin"]
        assert [e["iana_ids"] for e in origin if e["event"]=="offered_key_shares"]==[[4588],[29]]
        assert [e["iana_ids"] for e in origin if e["event"]=="offered_groups"]==[[4588,29],[4588,29]]
        assert sum(e["event"]=="hello_retry_request" for e in origin)==1
        for role,leg,group,host in (("client","front","X25519MLKEM768","proxy.test"),
                                    ("proxy","backend","x25519","origin.test")):
            hs=[e for e in streams[role] if e["event"]=="handshake" and e["leg"]==leg]
            assert len(hs)==1
            h=hs[0]
            assert h["ok"] and h["protocol"]=="TLSv1.3" and not h["session_reused"]
            assert h["group"]==group and h["certificate_status"]=="verified"
            assert h["verify_code"]==0 and h["verified_hostname"]==host
            assert c["observed"][leg+"_group"]==group
        proxy=streams["proxy"]
        policies=[e for e in proxy if e["event"]=="release_policy"]
        assert len(policies)==1
        policy=policies[0]
        assert policy["front_hybrid"] and not policy["backend_hybrid"]
        enabled=ident=="M06"
        assert policy["guard_mask"]==(3 if enabled else 0)
        assert policy["allowed"] is (not enabled)
        assert c["observed"]["delivered"] is (not enabled)
        events=[e for stream in streams.values() for e in stream]
        if enabled:
            assert not any(e["event"] in ("payload_write_attempt","write_progress","frame") for e in events)
            assert all(c["observed"][k]==0 for k in
                       ("payload_write_attempts","payload_bytes_accepted","framing_bytes_accepted"))
            close=[e for e in proxy if e["event"]=="alert" and e["direction"]=="sent"]
            assert [(e["leg"],e["description"]) for e in close]==[("backend",0),("front",0)]
            assert proxy.index(policy)<proxy.index(close[0])<proxy.index(close[1])
            assert c["observed"]["conformance"]=="satisfied_by_rejection"
        else:
            for kind,length in (("request",303),("response",319)):
                frames=[e for e in events if e["event"]=="frame" and e["kind"]==kind]
                assert len(frames)==4 and all(e["bytes"]==length for e in frames)
                assert len({e["hex"] for e in frames})==1
                assert len(bytes.fromhex(frames[0]["hex"]))==length
            ready=[e for e in proxy if e["event"]=="frame" and e["kind"]=="ready"]
            assert len(ready)==1 and ready[0]["direction"]=="sent" and ready[0]["hex"]=="5245414459"
            assert proxy.index(policy)<proxy.index(ready[0])
            assert c["observed"]["conformance"]=="violated"
    fig, ax = canvas(3.75)
    for left, ident, enabled in ((.02,"M05",False),(.52,"M06",True)):
        xs=[left+.035,left+.22,left+.405]
        ax.text(left+.22,.98,f"{ident}: guard {'enabled' if enabled else 'disabled'}, D = FB",
                ha="center",va="top",fontweight="bold",fontsize=9)
        for x,label in zip(xs,("Client","Gateway","Origin")):
            ax.text(x,.90,label,ha="center",fontsize=8.2)
            ax.plot([x,x],[.86,.10],color="#b8c0c6",linestyle="--",linewidth=.8,zorder=.5)
        arrow(ax,(xs[0],.82),(xs[1],.82),"F verified; group H",BLUE,True,dy=.014,size=7.3)
        arrow(ax,(xs[1],.71),(xs[2],.71),"H,C offer; initial share H",TEAL,dy=.012,size=7.0)
        arrow(ax,(xs[2],.63),(xs[1],.63),"HelloRetryRequest",TEAL,dy=.012,size=7.3)
        arrow(ax,(xs[1],.55),(xs[2],.55),"Replacement share C",TEAL,dy=.012,size=7.1)
        arrow(ax,(xs[1],.48),(xs[2],.48),"B verified; group C",TEAL,True,dy=.012,size=7.1)
        if not enabled:
            arrow(ax,(xs[1],.40),(xs[0],.40),"READY",ORANGE,dy=.012)
            arrow(ax,(xs[0],.33),(xs[1],.33),"Request: 303 bytes",dy=.012,size=7.2)
            arrow(ax,(xs[1],.27),(xs[2],.27),"Same request",dy=.012,size=7.3)
            arrow(ax,(xs[2],.21),(xs[1],.21),"Response: 319 bytes",dy=.012,size=7.2)
            arrow(ax,(xs[1],.15),(xs[0],.15),"Same response",dy=.012,size=7.3)
            box(ax,left,.015,.44,.075,"DELIVERY / POLICY VIOLATION",edge=RED,fill="#fbf0f0",size=8)
        else:
            box(ax,left+.09,.385,.30,.07,"Guard rejects B = C",edge=ORANGE,fill="#fff5e7",size=8)
            arrow(ax,(xs[1],.31),(xs[2],.31),"close_notify",ORANGE,dy=.012)
            arrow(ax,(xs[1],.24),(xs[0],.24),"close_notify",ORANGE,dy=.012)
            box(ax,left+.03,.105,.38,.11,"No READY or payload writes\n0 accepted application bytes",
                edge=TEAL,fill=PALE,size=8)
            box(ax,left,.015,.44,.075,"POLICY SATISFIED BY REFUSAL",edge=TEAL,fill="#eef6f4",size=8)
    return fig


def interventions(cases):
    fig, ax=canvas(2.5)
    rows=[("Backend requirement",["M05","M06","M13"],["Enable\nguard","Require\nF only"]),
          ("Frontend requirement",["M07","M09","M12"],["Enable\nguard","Require\nB only"]),
          ("Both requirements",["M11","M14"],["Require\nF and B"])]
    for j,(label,ids,changes) in enumerate(rows):
        y=.70-j*.30
        ax.text(.02,y+.19,label,fontsize=8.5,fontweight="bold",va="center")
        starts=[.02,.36,.70] if len(ids)==3 else [.02,.36]
        for x,ident in zip(starts,ids):
            c=cases[ident]; o=c["observed"]
            verdict=o["conformance"]
            word={"violated":"VIOLATION","satisfied_with_delivery":"DELIVERY",
                  "satisfied_by_rejection":"BLOCKED"}[verdict]
            color=RED if verdict=="violated" else TEAL
            groups_by_name={"X25519MLKEM768":"H","x25519":"C","X25519":"C"}
            groups=groups_by_name[o["front_group"]]+"/"+groups_by_name[o["backend_group"]]
            d={0:"none",1:"F",2:"B",3:"FB"}[c["declared_policy"]]
            box(ax,x,y,.26,.145,f"{ident}  {groups}  D={d}",word,color,PALE,size=8)
        for j2,change in enumerate(changes):
            arrow(ax,(starts[j2]+.26,y+.072),(starts[j2+1],y+.072),
                  change,dy=.025,size=7)
        if len(ids)==2:
            ax.text(.70,y+.07,"Same C/C TLS configuration;\nonly the declaration changes.",
                    fontsize=8,va="center")
    return fig


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--results",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args()
    raw=args.results.read_bytes(); record=json.loads(raw)
    assert record["status"]=="passed" and len(record["cases"])==16
    cases={c["name"]:c for c in record["cases"]}
    assert sum(c["observed"]["conformance"]=="violated" for c in cases.values())==3
    for a,b in (("M05","M06"),("M07","M09"),("M06","M13"),("M09","M12"),("M11","M14")):
        assert cases[a]["configuration"]==cases[b]["configuration"],(a,b)
    for a,b in (("M05","M06"),("M07","M09")):
        assert cases[a]["declared_policy"]==cases[b]["declared_policy"]==3
        assert not cases[a]["guard_enabled"] and cases[b]["guard_enabled"]
    for a,b in (("M06","M13"),("M09","M12"),("M11","M14")):
        assert cases[a]["guard_enabled"] and cases[b]["guard_enabled"]
        assert cases[a]["declared_policy"]!=cases[b]["declared_policy"]
    args.out.mkdir(parents=True,exist_ok=True)
    makers={"framework":framework,"methodology":methodology,
            "execution":lambda:sequence(cases),"interventions":lambda:interventions(cases)}
    outputs={}
    for name,make in makers.items():
        fig=make()
        target=args.out/(name+".pdf")
        fig.savefig(target,metadata={"CreationDate":None,"ModDate":None,
                                    "Creator":"build_figures.py; retained evidence only"})
        plt.close(fig)
        outputs[target.name]=hashlib.sha256(target.read_bytes()).hexdigest()
    manifest={"input_results_sha256":hashlib.sha256(raw).hexdigest(),
              "source_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "matplotlib":matplotlib.__version__,"font":"DejaVu Sans; embedded TrueType",
              "outputs":outputs,"scope":"Vector diagrams; no new TLS run; no measured timing axis."}
    (args.out/"figures_manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(json.dumps(manifest,indent=2))


if __name__=="__main__":
    main()
