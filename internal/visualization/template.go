package visualization

const htmlPrefix = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; connect-src 'none'; img-src 'none'; font-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>Maratus analysis map</title>
<style>
:root{color-scheme:light;--bg:#f3f5f7;--panel:#fff;--panel2:#f8fafc;--line:#d9e0e7;--line2:#b9c5d0;--text:#17212b;--muted:#667481;--brand:#087f8c;--artifact:#087f8c;--analysis-selection:#4263eb;--execution-root:#18864b;--invoked-target:#0e9270;--operation:#a35b00;--capability:#b42318;--coverage:#7c3aed;--focus:#0b69c7;--warning:#966300}*{box-sizing:border-box}html,body{height:100%;margin:0;background:var(--bg);color:var(--text);font:14px/1.48 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}button,input,select{font:inherit}button{color:var(--text);background:#fff;border:1px solid var(--line2);border-radius:8px;padding:.46rem .66rem;cursor:pointer}button:hover:not(:disabled),button[aria-pressed=true]{background:#eaf5f6;border-color:var(--brand)}button:disabled{cursor:default;opacity:.42}button:focus-visible,input:focus-visible,select:focus-visible,[tabindex]:focus-visible,summary:focus-visible{outline:3px solid #8ed8df;outline-offset:2px}.shell{display:grid;grid-template-rows:auto auto 1fr;height:100%}.topbar{display:flex;gap:1.1rem;align-items:flex-start;padding:1rem 1.25rem;background:#fff;border-bottom:1px solid var(--line)}.brand{font-weight:850;letter-spacing:.11em;color:var(--brand);font-size:1.08rem;white-space:nowrap}.headline{min-width:0;flex:1}.headline h1{font:750 1rem/1.3 ui-monospace,SFMono-Regular,Menlo,monospace;margin:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.headline p{color:var(--muted);font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;margin:.2rem 0 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.offline{font-size:.72rem;font-weight:700;color:#18723b;background:#edf9f1;border:1px solid #abdabb;border-radius:999px;padding:.22rem .55rem;white-space:nowrap}.overview-strip{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.65rem;padding:.75rem 1rem;background:var(--bg);border-bottom:1px solid var(--line)}.metric{background:#fff;border:1px solid var(--line);border-radius:10px;padding:.68rem .85rem;min-width:0;box-shadow:0 1px 2px #1822300a}.metric strong{display:block;font-size:1.05rem;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.metric span{display:block;color:var(--muted);font-size:.75rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.workspace{display:grid;grid-template-columns:258px minmax(450px,1fr) 326px;min-height:0}.sidebar,.details{background:var(--panel);overflow:auto;padding:.9rem}.sidebar{border-right:1px solid var(--line)}.details{border-left:1px solid var(--line)}h2{font-size:.76rem;letter-spacing:.09em;text-transform:uppercase;color:var(--muted);margin:1rem 0 .5rem}h2:first-child{margin-top:0}.view-switch{display:grid;grid-template-columns:1fr 1fr;gap:.35rem}.view-switch button{font-size:.8rem;text-align:left}.search,.select{width:100%;color:var(--text);background:#fff;border:1px solid var(--line2);border-radius:8px;padding:.55rem}.select{padding:.45rem;margin:.22rem 0 .48rem}.check{display:grid;grid-template-columns:auto auto 1fr auto;gap:.48rem;align-items:center;padding:.25rem 0}.check input{accent-color:var(--brand)}.type-count{color:var(--muted);font-size:.76rem}.dot{width:.7rem;height:.7rem;border-radius:3px;display:inline-block;background:var(--tone)}.artifact{--tone:var(--artifact)}.analysis-selection{--tone:var(--analysis-selection)}.execution-root{--tone:var(--execution-root)}.invoked-target{--tone:var(--invoked-target)}.operation{--tone:var(--operation)}.capability{--tone:var(--capability)}.coverage{--tone:var(--coverage)}.counts{display:grid;grid-template-columns:1fr auto;gap:.25rem .55rem;color:var(--muted)}.counts strong{color:var(--text);font-weight:600}.hint{color:var(--muted);font-size:.78rem;margin:.55rem 0}.disclosure{border-top:1px solid var(--line);margin-top:.8rem;padding-top:.65rem}.disclosure summary{cursor:pointer;color:var(--muted);font-size:.79rem;text-transform:uppercase;letter-spacing:.07em}.notes{margin:.45rem 0 0;padding-left:1.15rem;color:#715a24}.notes li{margin:.35rem 0}.notice-copy{color:#715a24}.canvas-wrap{position:relative;min-width:0;min-height:0;overflow:hidden;background-color:#f8fafc;background-image:radial-gradient(#d4dce4 1px,transparent 1px);background-size:22px 22px}.canvas-toolbar,.status{background:#fffffff2;border:1px solid var(--line);box-shadow:0 5px 18px #1822301a}.canvas-toolbar{position:absolute;z-index:2;top:.65rem;left:.65rem;display:flex;flex-wrap:wrap;gap:.34rem;max-width:calc(100% - 1.3rem);padding:.35rem;border-radius:9px}.status{position:absolute;z-index:2;left:.65rem;bottom:.65rem;max-width:calc(100% - 1.3rem);color:var(--muted);border-radius:7px;padding:.33rem .52rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.graph{width:100%;height:100%;display:block;touch-action:none}.edge{fill:none;stroke:#80909d;stroke-width:1.35;opacity:.55;vector-effect:non-scaling-stroke}.edge.connected{stroke:#b57500;opacity:1;stroke-width:2.3}.node{cursor:pointer}.node rect.card{fill:#fff;stroke:var(--tone);stroke-width:1.5;rx:8;vector-effect:non-scaling-stroke}.node .stripe{fill:var(--tone)}.node text{fill:var(--text);pointer-events:none}.node .type{fill:var(--tone);font-size:10px;font-weight:800;letter-spacing:.08em}.node .title{font-size:12px;font-weight:700}.node .subtitle{fill:var(--muted);font-size:10px}.node.dim{opacity:.2}.node.selected rect.card{stroke:var(--focus);stroke-width:3}.lane-label{fill:#617383;font-size:11px;font-weight:800;letter-spacing:.12em}.empty{fill:var(--muted);font-size:16px}.detail-empty{color:var(--muted);margin-top:.7rem}.detail-title{font-size:1rem;margin:.22rem 0 .3rem;overflow-wrap:anywhere}.badge{display:inline-block;border:1px solid currentColor;color:var(--tone,var(--muted));background:#fff;border-radius:999px;padding:.12rem .43rem;margin:.1rem .25rem .4rem 0;font:700 .7rem/1.35 ui-monospace,SFMono-Regular,Menlo,monospace}.detail-list{display:grid;grid-template-columns:minmax(7rem,38%) 1fr;gap:.36rem .6rem;margin-top:.6rem}.detail-list dt{color:var(--muted)}.detail-list dd{margin:0;overflow-wrap:anywhere;white-space:pre-wrap;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.connections{list-style:none;padding:0;margin:.5rem 0}.connection{display:block;width:100%;border-left:2px solid #80909d;border-radius:0;text-align:left;padding:.3rem .42rem;margin:.3rem 0;color:var(--muted);background:#f8fafc;overflow-wrap:anywhere}.connection:hover{color:var(--text);border-left-color:var(--brand)}.detail-controls{display:flex;gap:.35rem;margin:.5rem 0}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0;white-space:nowrap;border:0)}@media(max-width:1120px){.workspace{grid-template-columns:230px minmax(390px,1fr) 285px}.sidebar,.details{padding:.75rem}}@media(max-width:900px){.shell{height:auto;min-height:100%}.overview-strip{grid-template-columns:1fr 1fr}.workspace{grid-template-columns:1fr}.sidebar,.details{border:0;border-bottom:1px solid var(--line)}.canvas-wrap{height:68vh;min-height:450px}.details{min-height:220px}.topbar{flex-wrap:wrap}.offline{margin-left:auto}}@media(max-width:560px){.overview-strip{grid-template-columns:1fr 1fr;gap:.45rem;padding:.55rem}.metric{padding:.5rem .65rem}.topbar{padding:.75rem}.canvas-wrap{min-height:400px}.view-switch{grid-template-columns:1fr 1fr}}@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}
.shell{grid-template-rows:auto auto auto minmax(0,1fr);max-width:100vw;overflow:hidden}.page-tabs{display:flex;gap:.35rem;padding:.55rem 1rem;background:#09151e;border-bottom:1px solid var(--line)}.page-tabs button{min-width:7.5rem;text-align:center}.page-tabs button[aria-selected=true]{background:#1d3948;border-color:var(--brand)}.review-page{min-width:0;overflow:auto;padding:1rem}.review-inner{max-width:1280px;margin:0 auto}.review-intro{display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:.9rem}.review-intro h2{margin:0 0 .25rem;color:var(--text);font-size:1rem}.review-intro p{margin:0;color:var(--muted);max-width:72rem}.review-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.8rem}.review-card{min-width:0;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:.9rem}.review-card.wide{grid-column:1/-1}.review-card h2{margin:0 0 .65rem}.finding-list{display:grid;gap:.5rem}.finding{min-width:0;padding:.65rem;background:#09151e;border:1px solid #213846;border-radius:8px;overflow-wrap:anywhere}.finding-head{display:flex;align-items:flex-start;justify-content:space-between;gap:.7rem}.finding-title{font-weight:750;color:var(--text)}.finding-meta{color:var(--muted);font-size:.78rem;margin-top:.2rem;overflow-wrap:anywhere}.finding-badges{display:flex;gap:.25rem;flex-wrap:wrap;justify-content:flex-end}.empty-review{color:var(--muted);margin:.2rem 0}.workspace{position:relative;grid-template-columns:240px minmax(0,1fr);min-width:0;overflow:hidden}.workspace[hidden],.review-page[hidden]{display:none}.sidebar{min-width:0}.sidebar details.filter-panel{border-top:1px solid var(--line);margin-top:.8rem;padding-top:.65rem}.sidebar details.filter-panel>summary{cursor:pointer;color:var(--muted);font-size:.79rem;text-transform:uppercase;letter-spacing:.07em}.details{position:absolute;z-index:6;right:0;top:0;bottom:0;width:min(390px,calc(100% - 2rem));min-width:0;border-left:1px solid var(--line);box-shadow:-12px 0 28px #0009;transform:translateX(102%);transition:transform .16s ease}.details.open{transform:translateX(0)}.detail-heading{display:flex;align-items:center;justify-content:space-between;gap:.5rem}.detail-heading h2{margin:0}.detail-close{padding:.25rem .5rem}.canvas-wrap{min-width:0}.review-action{font-size:.76rem;padding:.28rem .48rem;white-space:nowrap}@media(max-width:900px){.shell{height:100%;min-height:0}.review-grid{grid-template-columns:1fr}.workspace{grid-template-columns:1fr;overflow:auto}.sidebar{border:0;border-bottom:1px solid var(--line);max-height:38vh}.canvas-wrap{height:auto;min-height:56vh}.details{position:fixed;top:0;height:100vh;width:min(420px,94vw);border-bottom:0}.topbar{flex-wrap:wrap}}@media(max-width:560px){.page-tabs{padding:.45rem .7rem}.page-tabs button{min-width:0;flex:1}.review-page{padding:.7rem}.review-intro{display:block}.review-grid{gap:.6rem}.overview-strip{grid-template-columns:1fr 1fr}.metric{padding:.5rem .65rem}.metric span{display:none}.offline{display:none}.finding-head{display:block}.finding-badges{justify-content:flex-start;margin-top:.35rem}.details{width:100vw}.detail-list{grid-template-columns:1fr}.detail-list dt{margin-top:.3rem}.topbar{padding:.65rem}}@media(prefers-reduced-motion:reduce){.details{transition:none}}
.shell{grid-template-columns:minmax(0,1fr);width:100%;max-width:100vw;min-width:0}.topbar,.overview-strip,.page-tabs,.review-page,.workspace{min-width:0;max-width:100%}
.sr-only{clip:rect(0,0,0,0)}.page-tabs{padding:.45rem 1rem;background:#fff;border-bottom:1px solid var(--line)}.page-tabs button{min-width:7rem;background:transparent;border-color:transparent;color:var(--muted)}.page-tabs button[aria-selected=true]{background:#eaf5f6;border-color:#b9dde1;color:#075d66}.review-page{padding:1.25rem;background:var(--bg)}.review-inner{max-width:1160px}.review-intro{margin:.2rem 0 1rem}.review-intro h2{font-size:1.35rem;letter-spacing:-.015em;text-transform:none;color:var(--text)}.review-intro p{max-width:54rem;font-size:.93rem}.review-grid{gap:.85rem}.review-card{padding:1rem;background:#fff;border:1px solid var(--line);border-radius:12px;box-shadow:0 1px 3px #1822300a}.review-card.primary{border-top:4px solid var(--capability)}.review-card h2{font-size:.73rem;color:#52616d;margin:0 0 .75rem}.finding-list{gap:.45rem}.finding{position:relative;padding:.68rem .72rem .68rem .82rem;background:#fafbfc;border:1px solid #e3e8ed;border-radius:8px}.finding:before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;border-radius:8px 0 0 8px;background:#9aa8b4}.finding[data-tone="capability"]:before{background:var(--capability)}.finding[data-tone="operation"]:before{background:var(--operation)}.finding[data-tone="activation"]:before{background:var(--execution-root)}.finding[data-tone="network"]:before{background:#4263eb}.finding[data-tone="observable"]:before{background:#7c3aed}.finding[data-tone="context"]:before{background:var(--brand)}.finding-title{font-size:.92rem}.finding-meta{font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}.finding-badges .badge{margin:0}.review-action{margin-top:.45rem;color:#075d66;background:transparent;border:0;padding:.15rem 0;text-decoration:underline;text-underline-offset:2px}.review-action:hover:not(:disabled){background:transparent;border-color:transparent}.review-limitations{margin-top:.9rem;background:#fff;border:1px solid var(--line);border-radius:10px;padding:.75rem .9rem}.review-limitations>summary{cursor:pointer;font-weight:700;color:#53616d}.review-limitations .finding-list{margin-top:.7rem}.review-limitations .notice-copy{font-size:.8rem}.details{box-shadow:-12px 0 28px #18223026}.empty-review{font-size:.86rem}@media(max-width:900px){.review-page{padding:.85rem}.review-grid{grid-template-columns:1fr}}@media(max-width:560px){.review-page{padding:.6rem}.review-card{padding:.8rem}.overview-strip{grid-template-columns:1fr 1fr}.finding-head{display:block}}
.review-detail>summary{display:flex;align-items:center;justify-content:space-between;gap:1rem;cursor:pointer;list-style:none}.review-detail>summary::-webkit-details-marker{display:none}.review-detail>summary h2{margin:0}.review-detail>summary span{color:var(--muted);font-size:.78rem}.review-detail[open]>summary{padding-bottom:.75rem;margin-bottom:.75rem;border-bottom:1px solid var(--line)}#review-capabilities,#review-technical-capabilities,#review-runtime-capabilities{grid-template-columns:repeat(2,minmax(0,1fr))}#review-context{grid-template-columns:repeat(2,minmax(0,1fr))}@media(max-width:760px){#review-capabilities,#review-technical-capabilities,#review-runtime-capabilities,#review-context{grid-template-columns:1fr}}
.review-path{display:flex;gap:.35rem;align-items:center;overflow-x:auto;margin:0 0 .8rem;padding:.12rem 0 .45rem;scrollbar-width:thin}.review-path span{flex:0 0 auto;color:var(--muted);font-size:.72rem;font-weight:750;text-transform:uppercase;letter-spacing:.07em}.review-path a{flex:0 0 auto;color:#075d66;background:#fff;border:1px solid var(--line);border-radius:999px;padding:.3rem .58rem;text-decoration:none;font-size:.78rem}.review-path a:hover{border-color:var(--brand);background:#eaf5f6}.review-grid{display:block}.review-card,.review-limitations{margin:0;background:transparent;border:0;border-top:1px solid var(--line);border-radius:0;box-shadow:none;padding:.78rem .15rem}.review-card.primary{border-top:1px solid var(--line)}.review-grid>.review-card:first-child{border-top:0}.review-detail>summary{min-height:2.1rem}.review-detail>summary h2{font-size:.82rem;color:#33424f}.review-detail>summary span{font-size:.76rem;text-align:right}.review-detail[open]>summary{padding-bottom:.55rem;margin-bottom:0;border-bottom:0}.finding-list,#review-capabilities,#review-technical-capabilities,#review-runtime-capabilities,#review-context{display:block}.finding{padding:.62rem .15rem;background:transparent;border:0;border-top:1px solid #e5eaef;border-radius:0}.finding:first-child{border-top:0}.finding:before{display:none}.finding-title{font-size:.9rem}.finding-meta{max-width:92rem}.review-limitations{margin-top:0}.review-limitations>summary{min-height:2.1rem;display:flex;align-items:center;cursor:pointer}.review-limitations .finding-list{margin-top:0}.empty-review{padding:.3rem .15rem}.review-action{margin-top:.3rem}.review-card[open]>.finding-list,.review-limitations[open]>.finding-list{animation:review-reveal .12s ease-out}@keyframes review-reveal{from{opacity:.35;transform:translateY(-2px)}to{opacity:1;transform:none}}@media(max-width:560px){.review-path{margin-left:-.1rem;margin-right:-.1rem}.review-detail>summary{align-items:flex-start}.review-detail>summary span{max-width:48%}}@media(prefers-reduced-motion:reduce){.review-card[open]>.finding-list,.review-limitations[open]>.finding-list{animation:none}}
:root{--surface:#fff;--surface-muted:#f7f9fb;--surface-hover:#eaf5f6;--shadow:0 1px 3px #1822300b;--network:#1e66f5;--observable:#8839ef;--context:#179299;--technical:#fe640b;--rail-capability:#d20f39;--rail-activation:#40a02b;--rail-network:#1e66f5;--rail-observable:#8839ef;--rail-context:#179299;--rail-technical:#fe640b;--rail-runtime:#7287fd;--rail-code:#209fb5;--rail-coverage:#df8e1d}
:root[data-theme="dark"]{color-scheme:dark;--bg:#0b1117;--panel:#111a22;--panel2:#16212b;--surface:#111a22;--surface-muted:#16212b;--surface-hover:#18333a;--line:#293744;--line2:#405364;--text:#e7edf2;--muted:#9baab7;--brand:#58c5cf;--artifact:#58c5cf;--analysis-selection:#8297ff;--execution-root:#55bd7b;--invoked-target:#45c7a1;--operation:#e6a34a;--capability:#f17b73;--coverage:#b89af4;--focus:#74b9ff;--warning:#e4b75e;--network:#8aadf4;--observable:#c6a0f6;--context:#8bd5ca;--technical:#f5a97f;--rail-capability:#ed8796;--rail-activation:#a6da95;--rail-network:#8aadf4;--rail-observable:#c6a0f6;--rail-context:#8bd5ca;--rail-technical:#f5a97f;--rail-runtime:#b7bdf8;--rail-code:#7dc4e4;--rail-coverage:#eed49f;--shadow:0 1px 3px #0008}
@media(prefers-color-scheme:dark){:root:not([data-theme]){color-scheme:dark;--bg:#0b1117;--panel:#111a22;--panel2:#16212b;--surface:#111a22;--surface-muted:#16212b;--surface-hover:#18333a;--line:#293744;--line2:#405364;--text:#e7edf2;--muted:#9baab7;--brand:#58c5cf;--artifact:#58c5cf;--analysis-selection:#8297ff;--execution-root:#55bd7b;--invoked-target:#45c7a1;--operation:#e6a34a;--capability:#f17b73;--coverage:#b89af4;--focus:#74b9ff;--warning:#e4b75e;--network:#8aadf4;--observable:#c6a0f6;--context:#8bd5ca;--technical:#f5a97f;--rail-capability:#ed8796;--rail-activation:#a6da95;--rail-network:#8aadf4;--rail-observable:#c6a0f6;--rail-context:#8bd5ca;--rail-technical:#f5a97f;--rail-runtime:#b7bdf8;--rail-code:#7dc4e4;--rail-coverage:#eed49f;--shadow:0 1px 3px #0008}}
.topbar,.page-tabs,.sidebar,.details{background:var(--surface)}button,.search,.select{color:var(--text);background:var(--surface);border-color:var(--line2)}button:hover:not(:disabled),button[aria-pressed=true]{background:var(--surface-hover)}.header-actions{display:flex;align-items:center;gap:.45rem;margin-left:auto}.theme-toggle{white-space:nowrap;padding:.28rem .55rem;color:var(--muted);background:var(--surface);font-size:.72rem}.offline{color:var(--execution-root);background:var(--surface-muted);border-color:var(--line2)}.metric{background:var(--surface);border-color:var(--line);box-shadow:var(--shadow)}.page-tabs button[aria-selected=true]{color:var(--brand);background:var(--surface-hover);border-color:var(--brand)}.review-path a{color:var(--brand);background:var(--surface);border-color:var(--line)}.review-path a:hover{background:var(--surface-hover)}
.review-card,.review-limitations{--section-tone:var(--line2);margin:0 0 .58rem;padding:0 .82rem .08rem;background:var(--surface);border:1px solid var(--line);border-radius:9px;box-shadow:var(--shadow)}.review-card.primary{border-top:1px solid var(--line)}.review-grid>.review-card:first-child{border-top:1px solid var(--line)}#review-capabilities-detail{--section-tone:var(--rail-capability)}#review-activation-detail{--section-tone:var(--rail-activation)}#review-network-detail{--section-tone:var(--rail-network)}#review-observables-detail{--section-tone:var(--rail-observable)}#review-loader-context-detail{--section-tone:var(--rail-context)}#review-context-detail{--section-tone:var(--rail-context)}#review-technical-capabilities-detail{--section-tone:var(--rail-technical)}#review-runtime-capabilities-detail{--section-tone:var(--rail-runtime)}#review-code-context-detail{--section-tone:var(--rail-code)}.review-grid>.review-card:not([id]){--section-tone:var(--rail-technical)}.review-limitations{--section-tone:var(--rail-coverage);margin-bottom:0}
.review-detail>summary,.review-limitations>summary{min-height:0;padding:.72rem 0;gap:.7rem;list-style:none}.review-detail>summary::-webkit-details-marker,.review-limitations>summary::-webkit-details-marker{display:none}.review-detail>summary h2{display:flex;flex:1;align-items:center;gap:.5rem;color:var(--text);font-size:.8rem;letter-spacing:.075em}.review-detail>summary h2:before,.review-limitations>summary:before{content:"";flex:0 0 auto;width:.5rem;height:.5rem;border-radius:2px;background:var(--section-tone)}.review-detail>summary span{max-width:55%;color:var(--muted)}.review-detail>summary:after,.review-limitations>summary:after{content:"";flex:0 0 auto;width:.42rem;height:.42rem;margin:-.2rem .18rem 0 .12rem;border-right:2px solid var(--muted);border-bottom:2px solid var(--muted);transform:rotate(45deg);transition:transform .12s ease}.review-detail[open]>summary:after,.review-limitations[open]>summary:after{margin-top:.2rem;transform:rotate(225deg)}.review-detail[open]>summary{padding-bottom:.6rem;margin-bottom:.18rem;border-bottom:1px solid var(--line)}.review-card>.finding-list,.review-limitations>.finding-list{padding:.16rem 0 .55rem}
.finding{--finding-tone:var(--line2);margin:.34rem 0;padding:.58rem .66rem;background:var(--surface-muted);border:1px solid var(--line);border-left:3px solid var(--finding-tone);border-radius:7px}.finding:first-child{border-top:1px solid var(--line)}.finding[data-tone="capability"]{--finding-tone:var(--rail-capability)}.finding[data-tone="activation"]{--finding-tone:var(--rail-activation)}.finding[data-tone="network"]{--finding-tone:var(--rail-network)}.finding[data-tone="observable"]{--finding-tone:var(--rail-observable)}.finding[data-tone="context"]{--finding-tone:var(--rail-context)}.finding[data-tone="operation"]{--finding-tone:var(--rail-technical)}.finding[data-tone="coverage"]{--finding-tone:var(--rail-coverage)}.review-card>.finding-list>.finding,.review-limitations>.finding-list>.finding{--finding-tone:var(--section-tone)}.finding-title{color:var(--text)}.badge{background:var(--surface)}.review-action{color:var(--brand)}.review-action:hover:not(:disabled){color:var(--text);background:transparent}.notice-copy,.notes{color:var(--warning)}
.canvas-wrap{background-color:var(--panel2);background-image:radial-gradient(var(--line) 1px,transparent 1px)}.canvas-toolbar,.status{background:var(--surface);border-color:var(--line);box-shadow:var(--shadow)}.node rect.card{fill:var(--surface)}.connection{color:var(--muted);background:var(--surface-muted)}.details{box-shadow:-12px 0 28px #0007}
@media(max-width:560px){.header-actions{width:100%;margin-left:0}.theme-toggle{margin-left:auto}.review-card,.review-limitations{padding-left:.68rem;padding-right:.68rem}.review-detail>summary span{max-width:44%}}
@media(min-width:561px) and (max-width:900px){.overview-strip{grid-template-columns:repeat(4,minmax(0,1fr));gap:.4rem;padding:.55rem .65rem}.metric{padding:.5rem .58rem}.metric strong{font-size:.92rem}.metric span{font-size:.68rem}}
@media(prefers-reduced-motion:reduce){.review-detail>summary:after,.review-limitations>summary:after{transition:none}}
.finding-instances{margin-top:.45rem;min-width:0}.finding-instances>summary,.finding-instance>summary{cursor:pointer;color:var(--brand);overflow-wrap:anywhere}.finding-instance{padding:.55rem 0;border-top:1px solid var(--line);margin-top:.4rem;min-width:0}.finding-instance .detail-list{margin:.6rem 0;overflow-wrap:anywhere}.finding-instance summary{font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}.finding-instance .review-action{margin-top:0}
</style>
</head>
<body>
<div class="shell">
  <header class="topbar"><div class="brand">MARATUS</div><div class="headline"><h1 id="page-title">Analysis map</h1><p id="artifact-name">Loading report…</p></div><div class="header-actions"><button type="button" class="theme-toggle" id="theme-toggle" aria-label="Theme: automatic">Theme: Auto</button><div class="offline">OFFLINE · SINGLE FILE</div></div></header>
  <section class="overview-strip" aria-label="Analysis summary">
    <div class="metric"><strong id="metric-capabilities">—</strong><span id="metric-capabilities-detail">Capabilities</span></div>
    <div class="metric"><strong id="metric-support">—</strong><span id="metric-support-detail">Match support</span></div>
    <div class="metric"><strong id="metric-behavior">—</strong><span id="metric-behavior-detail">Modeled behavior</span></div>
    <div class="metric"><strong id="metric-evidence">—</strong><span id="metric-evidence-detail">Evidence</span></div>
  </section>
  <nav class="page-tabs" aria-label="Report views"><button type="button" id="review-tab" aria-selected="true">Review</button><button type="button" id="graph-tab" aria-selected="false">Evidence graph</button></nav>
  <section class="review-page" id="review-page" aria-label="Analysis review">
    <div class="review-inner">
      <div class="review-intro"><div><h2>Static findings</h2><p>What the artifact can do, how it may be selected, and which facts support those conclusions. CONNECTED means modeled reachability, not observed execution.</p></div></div>
      <nav class="review-path" aria-label="Report sections"><span>Review</span><a href="#review-capabilities-detail">Behavior</a><a href="#review-activation-detail">Activation</a><a href="#review-network-detail">Network</a><a href="#review-observables-detail">Indicators</a><a href="#review-loader-context-detail">Loader</a><a href="#review-context-detail">Artifact context</a></nav>
      <div class="review-grid">
        <details class="review-card wide review-detail primary" id="review-capabilities-detail" open><summary><h2 id="review-capabilities-title">Behavioral capabilities</h2><span id="review-capabilities-summary">Operation-backed findings</span></summary><div class="finding-list" id="review-capabilities"></div></details>
        <details class="review-card wide review-detail" id="review-activation-detail" open><summary><h2 id="review-activation-title">Conditional activation</h2><span id="review-activation-summary">Host selection and entrypoints</span></summary><div class="finding-list" id="review-activation"></div></details>
        <details class="review-card wide review-detail" id="review-network-detail"><summary><h2 id="review-network-title">Network evidence</h2><span id="review-network-summary">Calls and destinations</span></summary><div class="finding-list" id="review-network"></div></details>
        <details class="review-card wide review-detail" id="review-observables-detail"><summary><h2 id="review-observables-title">Static observables</h2><span id="review-observables-summary">Prioritized indicators and data</span></summary><div class="finding-list" id="review-observables"></div></details>
        <details class="review-card wide review-detail" id="review-loader-context-detail"><summary><h2>Mach-O loader context</h2><span id="review-loader-context-summary">Show runtime paths and non-system dependencies</span></summary><div class="finding-list" id="review-loader-context"></div></details>
        <details class="review-card wide review-detail" id="review-context-detail"><summary><h2 id="review-context-title">Artifact and build context</h2><span id="review-context-summary">Show signing, entitlement, and build facts</span></summary><div class="finding-list" id="review-context"></div></details>
        <details class="review-card wide review-detail" id="review-technical-capabilities-detail"><summary><h2 id="review-technical-capabilities-title">Technical capabilities</h2><span id="review-technical-capabilities-summary">Show rule-backed technical conclusions</span></summary><div class="finding-list" id="review-technical-capabilities"></div></details>
        <details class="review-card wide review-detail" id="review-runtime-capabilities-detail"><summary><h2>Runtime and standard-library support surface</h2><span id="review-runtime-capabilities-summary">Show bundled support primitives</span></summary><div class="finding-list" id="review-runtime-capabilities"></div></details>
        <details class="review-card wide review-detail" id="review-code-context-detail"><summary><h2>Native code context</h2><span id="review-code-context-summary">Show retained function identity</span></summary><div class="finding-list" id="review-code-context"></div></details>
        <details class="review-card wide review-detail"><summary><h2 id="review-behavior-title">Underlying modeled operations</h2><span>Show low-level actions retained from code</span></summary><div class="finding-list" id="review-behavior"></div></details>
      </div>
      <details class="review-limitations" id="review-coverage-detail" hidden><summary id="review-coverage-title">Analysis notes</summary><div class="finding-list" id="review-coverage"></div></details>
    </div>
  </section>
  <main class="workspace" id="graph-page" hidden>
    <aside class="sidebar" aria-label="Graph controls">
      <h2>Explore evidence</h2><label class="sr-only" for="search">Search graph</label><input class="search" id="search" type="search" placeholder="Search facts and evidence…" autocomplete="off">
      <h2>Graph view</h2><div class="view-switch" id="view-switch"><button type="button" data-view="overview" aria-pressed="true">Core flow</button><button type="button" data-view="behavior" aria-pressed="false">Behavior</button><button type="button" data-view="full" aria-pressed="false">All facts</button></div>
      <p class="hint" id="view-help">Core flow keeps artifacts, conditional activation, modeled behavior, and capability matches visible.</p>
      <details class="filter-panel"><summary>Advanced filters</summary><h2>Node types</h2><div id="type-filters"></div><h2>Analysis state</h2><label for="support">Support</label><select class="select" id="support"><option value="">Any support</option><option>DIRECT</option><option>CORROBORATED</option><option>HEURISTIC</option></select><label for="connectivity">Execution connectivity</label><select class="select" id="connectivity"><option value="">Any connectivity</option><option>CONNECTED</option><option>UNCONNECTED</option><option>UNKNOWN</option></select><label for="status">Artifact / coverage status</label><select class="select" id="status"><option value="">Any status</option><option>analyzed</option><option>partial</option><option>skipped</option></select><h2>Rendered / report</h2><div class="counts" id="counts"></div></details>
      <details class="filter-panel"><summary>Report notes</summary><details class="disclosure" id="diagnostic-section"><summary id="diagnostic-summary">Diagnostics</summary><ul class="notes" id="diagnostics"></ul></details><details class="disclosure" id="omission-section"><summary id="omission-summary">Bounded view notes</summary><ul class="notes" id="omissions"></ul></details></details>
      <div hidden><details id="observable-section"><summary id="observable-summary"></summary><ul id="observables"></ul></details><details id="network-section"><summary id="network-summary"></summary><ul id="network-activity"></ul></details></div>
    </aside>
    <section class="canvas-wrap" id="canvas-wrap" aria-label="Interactive analysis graph">
      <div class="canvas-toolbar"><button type="button" id="fit">Fit</button><button type="button" id="zoom-in" aria-label="Zoom in">＋</button><button type="button" id="zoom-out" aria-label="Zoom out">−</button><button type="button" id="focus-neighbors" disabled>Focus neighbors</button><button type="button" id="clear">Reset</button></div>
      <svg class="graph" id="graph" role="group" aria-label="Artifact and behavior relationship graph" aria-describedby="graph-help"><defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L0,6 L8,3 z" fill="#4b6675"/></marker></defs><g id="scene"><g id="edges"></g><g id="nodes"></g></g></svg>
      <div class="status" id="status-line" aria-live="polite"></div>
    </section>
    <aside class="details" id="details-panel" aria-label="Selected node details"><div class="detail-heading"><h2>Fact details</h2><button type="button" class="detail-close" id="detail-close" aria-label="Close details">Close</button></div><div id="detail"><p class="detail-empty">Select a node to inspect its modeled fields and follow its connections.</p></div><p class="hint" id="graph-help">Wheel to zoom · drag the background to pan · Arrow keys move between nodes · Enter or Space selects.</p></aside>
  </main>
</div>
<script id="scan-data" type="application/json">`

const htmlSuffix = `</script>
<script>
"use strict";
(() => {
  const dataElement = document.getElementById("scan-data");
  const data = JSON.parse(dataElement.textContent);
  dataElement.remove();
  const TYPES = [
    ["artifact", "Artifacts", "artifacts"], ["analysis-selection", "Analysis selections", "analysis_selections"],
    ["execution-root", "Execution roots", "execution_roots"], ["invoked-target", "Invoked targets", "invoked_targets"],
    ["operation", "Modeled operations", "modeled_operations"],
    ["capability", "Capability matches", "capability_matches"], ["coverage", "Coverage", "coverage"]
  ];
  const TYPE_LABEL = {artifact: "Artifact", "analysis-selection": "Analysis selection", "execution-root": "Execution root", "invoked-target": "Invoked target", operation: "Modeled operation", capability: "Capability match", coverage: "Coverage"};
  const ALL_TYPES = TYPES.map(item => item[0]);
  const VIEW_TYPES = {
    overview: ["artifact", "execution-root", "invoked-target", "operation", "capability"],
    behavior: ["artifact", "execution-root", "invoked-target", "operation", "capability"],
    full: ALL_TYPES
  };
  const VIEW_HELP = {
    overview: "Overview keeps artifacts, conditional activation, modeled behavior, and capability matches visible.",
    behavior: "Behavior adds modeled operations so capability support and ownership can be traced.",
    full: "Full graph displays every node retained by the bounded HTML projection.",
    custom: "Custom view reflects the node types selected below."
  };
  const MIN_ZOOM = .02, MAX_ZOOM = 3;
  const state = {enabled: new Set(VIEW_TYPES.overview), mode: "overview", neighborhood: false, selected: "", focused: "", refocus: false, zoom: 1, x: 40, y: 70, positions: new Map(), fit: true};
  const graph = document.getElementById("graph"), scene = document.getElementById("scene");
  const edgeLayer = document.getElementById("edges"), nodeLayer = document.getElementById("nodes");
  const search = document.getElementById("search"), support = document.getElementById("support");
  const connectivity = document.getElementById("connectivity"), statusFilter = document.getElementById("status");
  const byID = new Map(data.nodes.map(node => [node.id, node]));
  const byRecord = new Map(), byReviewGroup = new Map();
  data.nodes.forEach(node => {
    if (!node.record_id) return;
    byRecord.set(node.type + "\u0000" + node.record_id, node);
    if (node.review_group) {
      if (!byReviewGroup.has(node.review_group)) byReviewGroup.set(node.review_group, []);
      byReviewGroup.get(node.review_group).push(node);
    }
  });
  const searchIndex = new Map(data.nodes.map(node => [node.id, JSON.stringify(node).toLowerCase()]));
  const summary = data.summary || {};
  const projection = data.projection || {};
  const reviewPage = document.getElementById("review-page"), graphPage = document.getElementById("graph-page");
  const reviewTab = document.getElementById("review-tab"), graphTab = document.getElementById("graph-tab");
  const themeToggle = document.getElementById("theme-toggle"), themeModes = ["auto", "dark", "light"];
  let themeMode = "auto";

  function setTheme(mode) {
    themeMode = mode;
    if (mode === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", mode);
    const label = mode.charAt(0).toUpperCase() + mode.slice(1);
    themeToggle.textContent = "Theme: " + label;
    themeToggle.setAttribute("aria-label", "Theme: " + (mode === "auto" ? "automatic" : mode));
  }
  themeToggle.addEventListener("click", () => setTheme(themeModes[(themeModes.indexOf(themeMode) + 1) % themeModes.length]));

  function setPage(page) {
    const graphSelected = page === "graph";
    reviewPage.hidden = graphSelected; graphPage.hidden = !graphSelected;
    reviewTab.setAttribute("aria-selected", String(!graphSelected)); graphTab.setAttribute("aria-selected", String(graphSelected));
    if (graphSelected) { state.fit = true; scheduleRender(); }
  }
  reviewTab.addEventListener("click", () => setPage("review"));
  graphTab.addEventListener("click", () => setPage("graph"));

  function reviewEmpty(container, text) { const item = document.createElement("p"); item.className = "empty-review"; item.textContent = text; container.append(item); }
  function exploreRecord(node) {
    search.value = ""; support.value = ""; connectivity.value = ""; statusFilter.value = "";
    setMode("full"); setPage("graph");
    state.selected = node.id; state.focused = node.id; state.refocus = true; state.neighborhood = true; render();
  }
  function addFindingInstances(item, selection) {
    const nodes = selection.group ? (byReviewGroup.get(selection.group) || []) : [byRecord.get(selection.type + "\u0000" + selection.id)].filter(Boolean);
    const total = selection.count || nodes.length;
    if (!nodes.length) { reviewEmpty(item, "Backing instances are outside this bounded HTML view. Inspect the canonical JSON report."); return; }
    const instances = document.createElement("details"); instances.className = "finding-instances";
    const heading = document.createElement("summary"); heading.textContent = "Review " + nodes.length + (nodes.length < total ? " of " + total : "") + (total === 1 ? " instance" : " instances"); instances.append(heading);
    let populated = false;
    instances.addEventListener("toggle", () => {
      if (!instances.open || populated) return;
      populated = true;
      nodes.forEach(node => {
        const entry = document.createElement("details"); entry.className = "finding-instance";
        const label = document.createElement("summary");
        const context = (node.details || []).filter(row => ["Artifact path", "Architecture", "Architecture scopes", "Execution root IDs"].includes(row.label)).map(row => row.value);
        label.textContent = [node.record_id].concat(context).filter(Boolean).join(" · "); entry.append(label);
        const fields = document.createElement("dl"); fields.className = "detail-list";
        (node.details || []).forEach(row => { const term = document.createElement("dt"), value = document.createElement("dd"); term.textContent = row.label; value.textContent = row.value; fields.append(term, value); }); entry.append(fields);
        const action = document.createElement("button"); action.type = "button"; action.className = "review-action"; action.textContent = "Open this instance in graph"; action.addEventListener("click", () => exploreRecord(node)); entry.append(action);
        instances.append(entry);
      });
      if (nodes.length < total) reviewEmpty(instances, "Other instances are outside this bounded HTML view. Inspect the canonical JSON report.");
    });
    item.append(instances);
  }
  function addReviewFinding(container, titleText, metaParts, badges, query, tone) {
    const item = document.createElement("article"); item.className = "finding"; if (tone) item.dataset.tone = tone;
    const head = document.createElement("div"); head.className = "finding-head";
    const title = document.createElement("div"); title.className = "finding-title"; title.textContent = titleText;
    const badgeBox = document.createElement("div"); badgeBox.className = "finding-badges";
    (badges || []).filter(Boolean).forEach(value => { const badge = document.createElement("span"); badge.className = "badge"; badge.textContent = value; badgeBox.append(badge); });
    head.append(title, badgeBox); item.append(head);
    const meta = (metaParts || []).filter(Boolean).join(" · ");
    if (meta) { const detail = document.createElement("div"); detail.className = "finding-meta"; detail.textContent = meta; item.append(detail); }
    if (query && typeof query === "object") addFindingInstances(item, query);
    else if (query) { const action = document.createElement("button"); action.type = "button"; action.className = "review-action"; action.textContent = "Search related facts"; action.addEventListener("click", () => { search.value = query; setMode("full"); setPage("graph"); }); item.append(action); }
    container.append(item);
  }

  function renderReview() {
    const activation = document.getElementById("review-activation"), capabilities = document.getElementById("review-capabilities"), technicalCapabilities = document.getElementById("review-technical-capabilities"), runtimeCapabilities = document.getElementById("review-runtime-capabilities"), behaviorList = document.getElementById("review-behavior");
    const network = document.getElementById("review-network"), observables = document.getElementById("review-observables"), coverage = document.getElementById("review-coverage");
    const activations = projection.conditional_activation || [];
    if (!activations.length) reviewEmpty(activation, "No trusted static host-selection or execution-root relationship was established.");
    activations.forEach(item => addReviewFinding(activation, item.name || item.interpreter || item.kind, [item.kind, item.interpreter], [item.connectivity], {type: item.kind.split(":")[0], id: item.id, count: 1}, "activation"));
    const capabilityItems = projection.capabilities || [], runtimeCapabilityItems = capabilityItems.filter(item => item.category === "runtime-support"), technicalCapabilityItems = capabilityItems.filter(item => item.category === "technical-primitive"), behavioralCapabilityItems = capabilityItems.filter(item => item.category === "behavior");
    if (!behavioralCapabilityItems.length) reviewEmpty(capabilities, capabilityItems.length ? "No higher-level behavioral capability was established. Technical and runtime inventories remain available below." : "No operation-backed capability matches. This is not a safety verdict.");
    document.getElementById("review-capabilities-summary").textContent = behavioralCapabilityItems.length ? countLabel(behavioralCapabilityItems.length, "finding", "findings") : "No higher-level finding established";
    const renderCapability = (container, item) => {
      const implementations = (item.implementations || []).map(value => value.replace(/^[^:]+:\s*/, ""));
      const operationCount = item.operation_count || 0;
      const meta = [item.namespace, item.count > 1 ? item.count + " matches" : "", operationCount ? "backed by " + (item.operation_count_limited ? "at least " : "") + operationCount + (operationCount === 1 ? " operation" : " operations") : "", implementations.length ? "via " + implementations.join(", ") : "", (item.resources || []).length ? "resources: " + item.resources.join(", ") : "", (item.unresolved || []).length ? "unresolved: " + item.unresolved.join(", ") : ""];
      addReviewFinding(container, item.title, meta, [].concat(item.attack || [], [item.support, item.connectivity]), {group: item.group_id, count: item.count}, "capability");
    };
    behavioralCapabilityItems.forEach(item => renderCapability(capabilities, item));
    const technicalDetail = document.getElementById("review-technical-capabilities-detail");
    if (!technicalCapabilityItems.length) technicalDetail.hidden = true;
    else {
      document.getElementById("review-technical-capabilities-summary").textContent = "Show " + technicalCapabilityItems.length + " rule-backed technical " + (technicalCapabilityItems.length === 1 ? "conclusion" : "conclusions");
      technicalCapabilityItems.forEach(item => renderCapability(technicalCapabilities, item));
    }
    const runtimeDetail = document.getElementById("review-runtime-capabilities-detail");
    if (!runtimeCapabilityItems.length) runtimeDetail.hidden = true;
    else {
      document.getElementById("review-runtime-capabilities-summary").textContent = "Show " + runtimeCapabilityItems.length + " bundled support " + (runtimeCapabilityItems.length === 1 ? "capability" : "capabilities");
      runtimeCapabilityItems.forEach(item => renderCapability(runtimeCapabilities, item));
    }
    const codeItems = projection.code_context || [], codeDetail = document.getElementById("review-code-context-detail"), codeList = document.getElementById("review-code-context");
    if (!codeItems.length) codeDetail.hidden = true;
    else {
      const omitted = projection.code_context_omitted || 0;
      document.getElementById("review-code-context-summary").textContent = "Show " + codeItems.length + " exact functions" + (omitted ? " (" + omitted + " more omitted)" : "");
      codeItems.forEach(item => addReviewFinding(codeList, item.name, [item.logical_path, item.kind, item.architecture, "identity only; behavior not implied"], [item.origin], item.name, "context"));
    }
    const behaviors = projection.modeled_behavior || [];
    if (!behaviors.length) reviewEmpty(behaviorList, "No modeled operations were retained.");
    behaviors.forEach(item => {
      const meta = [].concat(item.requested_arguments || [], item.resources || [], (item.unresolved || []).map(value => value + " unresolved"), item.implementations || []);
      addReviewFinding(behaviorList, item.kind + (item.count > 1 ? " × " + item.count : ""), meta, [item.support, item.connectivity], {group: item.group_id, count: item.count}, "operation");
    });
    const networkItems = projection.network_activity || [];
    document.getElementById("review-activation-summary").textContent = activations.length ? countLabel(activations.length, "conditional path", "conditional paths") : "No trusted static path established";
    document.getElementById("review-network-summary").textContent = networkItems.length ? countLabel(networkItems.length, "network record", "network records") : "No network evidence established";
    if (!networkItems.length) reviewEmpty(network, "No network operation, exact called network API, or retained destination was established.");
    networkItems.forEach(item => {
      const destinations = (item.destinations || []).length ? item.destinations : ["destination unresolved"];
      const meta = [item.implementation, (item.unresolved || []).length ? "unresolved: " + item.unresolved.join(", ") : ""].filter(Boolean);
      addReviewFinding(network, destinations.join(", "), meta, [item.static_only ? "API evidence only" : (item.direction || "network operation"), item.support], item.implementation || destinations[0], "network");
    });
    const observableItems = projection.static_observables || [], loaderItems = observableItems.filter(item => (item.category || "").startsWith("Mach-O ")), indicatorItems = observableItems.filter(item => !(item.category || "").startsWith("Mach-O "));
    document.getElementById("review-observables-summary").textContent = indicatorItems.length ? countLabel(indicatorItems.length, "retained observation", "retained observations") : "No prioritized observation retained";
    if (!indicatorItems.length) reviewEmpty(observables, "No prioritized static observables were retained.");
    indicatorItems.forEach(item => addReviewFinding(observables, item.value, [item.category, "static data only"], [], item.value, "observable"));
    const loaderDetail = document.getElementById("review-loader-context-detail"), loaderList = document.getElementById("review-loader-context");
    if (!loaderItems.length) loaderDetail.hidden = true;
    else {
      document.getElementById("review-loader-context-summary").textContent = "Show " + countLabel(loaderItems.length, "exact declaration", "exact declarations");
      loaderItems.forEach(item => addReviewFinding(loaderList, item.value, [item.category, "declaration only; runtime resolution not established"], [], item.value, "context"));
    }
    const context = document.getElementById("review-context"), contextItems = projection.artifact_context || [];
    document.getElementById("review-context-summary").textContent = contextItems.length ? "Show " + countLabel(contextItems.length, "artifact fact", "artifact facts") : "No prioritized artifact fact retained";
    if (!contextItems.length) reviewEmpty(context, "No prioritized signing, entitlement, package, or build context was retained.");
    contextItems.forEach(item => addReviewFinding(context, item.value || item.kind, [item.kind, item.count > 1 ? item.count + " artifacts" : ""], [item.support], item.value || item.kind, "context"));
    const coverageItems = projection.coverage || [];
    if (!coverageItems.length && !(data.diagnostics || []).length) reviewEmpty(coverage, "No extractor limitations or diagnostics were recorded.");
    coverageItems.forEach(item => addReviewFinding(coverage, item.area, [item.detail], [item.status], item.area, "coverage"));
    (data.diagnostics || []).forEach(item => addReviewFinding(coverage, "Diagnostic", [item], ["review"], "", "coverage"));
  }

  document.title = data.title;
  document.getElementById("page-title").textContent = data.title;
  const build = [data.tool, data.tool_version].filter(Boolean).join(" ");
  const commit = data.tool_commit ? "commit " + data.tool_commit.slice(0, 12) + (data.tool_modified ? " (modified)" : "") : (data.tool_modified ? "modified build" : "");
  const analysis = data.analysis || {};
  const analysisReported = Object.values(analysis).some(value => value !== false && value !== 0 && value !== "");
  const analysisMode = analysisReported ? [analysis.architecture ? "arch=" + analysis.architecture : "", analysis.include_unreferenced ? "unreferenced content included" : "execution-relevant content", analysis.expand_containers ? "container expansion enabled" : "container expansion disabled", analysis.allow_dmg_mount ? "read-only DMG mounting allowed" : "", analysis.zip_password_supplied ? "ZIP password supplied" : ""].filter(Boolean).join(", ") : "";
  const catalog = data.rule_catalog_digest ? "catalog " + data.rule_catalog_digest.slice(0, 19) : "";
  document.getElementById("artifact-name").textContent = [data.artifact || "Artifact name not reported", build, commit, data.ruleset_version, catalog, analysisMode].filter(Boolean).join(" · ");

  function countLabel(value, singular, plural) { return String(value || 0) + " " + ((value || 0) === 1 ? singular : plural); }
  const totalMatches = data.source_counts.capability_matches || 0;
  document.getElementById("metric-capabilities").textContent = countLabel(summary.capabilities, "capability", "capabilities");
  document.getElementById("metric-capabilities-detail").textContent = countLabel(totalMatches, "match", "matches") + " retained in report";
  const supportSummary = [[summary.direct_matches, "direct"], [summary.corroborated_matches, "corroborated"], [summary.heuristic_matches, "heuristic"]].filter(item => item[0]).map(item => item[0] + " " + item[1]);
  document.getElementById("metric-support").textContent = supportSummary.join(" · ") || "No matches";
  const execution = [[summary.connected_matches, "connected"], [summary.unconnected_matches, "unconnected"], [summary.unknown_matches, "unknown"]].filter(item => item[0]).map(item => item[0] + " " + item[1]);
  document.getElementById("metric-support-detail").textContent = execution.join(" · ") || "No execution connectivity recorded";
  document.getElementById("metric-behavior").textContent = countLabel(data.source_counts.modeled_operations, "modeled operation", "modeled operations");
  document.getElementById("metric-behavior-detail").textContent = countLabel(data.source_counts.execution_roots, "activation root", "activation roots") + " · " + countLabel(data.source_counts.invoked_targets, "invoked target", "invoked targets");
  const limitationCount = summary.coverage_limitations || 0, diagnosticCount = data.source_counts.diagnostics || 0;
  const noteCount = limitationCount + diagnosticCount;
  document.getElementById("review-coverage-detail").hidden = noteCount === 0;
	document.getElementById("review-coverage-title").textContent = "Analysis notes (" + String(noteCount) + ")";
  const observableCount = (projection.static_observables || []).length, networkCount = (projection.network_activity || []).length;
  document.getElementById("metric-evidence").textContent = countLabel(observableCount, "observable", "observables") + " · " + countLabel(networkCount, "network path", "network paths");
  document.getElementById("metric-evidence-detail").textContent = "Open the evidence graph for exact lineage";

  const filters = document.getElementById("type-filters"), boxes = new Map();
  TYPES.forEach(([type, label, sourceKey]) => {
    const row = document.createElement("label"); row.className = "check " + type;
    const box = document.createElement("input"); box.type = "checkbox"; box.checked = state.enabled.has(type); box.value = type; boxes.set(type, box);
    const dot = document.createElement("span"); dot.className = "dot"; dot.setAttribute("aria-hidden", "true");
    const text = document.createElement("span"); text.textContent = label;
    const count = document.createElement("span"); count.className = "type-count"; count.textContent = String(data.shown_counts[sourceKey] || 0);
    box.addEventListener("change", () => { box.checked ? state.enabled.add(type) : state.enabled.delete(type); state.mode = "custom"; state.neighborhood = false; updateViewControls(); state.fit = true; scheduleRender(); });
    row.append(box, dot, text, count); filters.append(row);
  });

  const counts = document.getElementById("counts");
  TYPES.forEach(([, label, sourceKey]) => {
    const name = document.createElement("span"); name.textContent = label;
    const value = document.createElement("strong"); value.textContent = String(data.shown_counts[sourceKey] || 0) + " / " + String(data.source_counts[sourceKey] || 0);
    counts.append(name, value);
  });
  const connectionName = document.createElement("span"); connectionName.textContent = "Connections";
  const connectionValue = document.createElement("strong"); connectionValue.textContent = String(data.shown_counts.links || 0); counts.append(connectionName, connectionValue);

  function fillNotes(sectionID, summaryID, listID, label, notes) {
    const section = document.getElementById(sectionID), list = document.getElementById(listID);
    if (!notes.length) { section.hidden = true; return; }
    document.getElementById(summaryID).textContent = label + " (" + notes.length + ")";
    notes.forEach(note => { const item = document.createElement("li"); item.textContent = note; list.append(item); });
  }
  fillNotes("diagnostic-section", "diagnostic-summary", "diagnostics", "Diagnostics", data.diagnostics || []);
  fillNotes("omission-section", "omission-summary", "omissions", "Bounded view notes", data.omission_notes || []);
  const observables = (projection.static_observables || []).map(item => item.category + ": " + item.value);
  const networkActivity = (projection.network_activity || []).map(item => [item.direction || "network", (item.destinations || []).join(", ") || "unresolved destination", item.implementation || ""].filter(Boolean).join(" · "));
  fillNotes("observable-section", "observable-summary", "observables", "Static observables", observables);
  fillNotes("network-section", "network-summary", "network-activity", "Network activity", networkActivity);

  const viewButtons = [...document.querySelectorAll("[data-view]")];
  function updateViewControls() {
    viewButtons.forEach(button => button.setAttribute("aria-pressed", String(button.dataset.view === state.mode)));
    boxes.forEach((box, type) => { box.checked = state.enabled.has(type); });
    document.getElementById("view-help").textContent = VIEW_HELP[state.mode];
  }
  function setMode(mode) {
    state.mode = mode; state.enabled = new Set(VIEW_TYPES[mode]); state.neighborhood = false; state.selected = ""; state.fit = true;
    updateViewControls(); scheduleRender();
  }
  viewButtons.forEach(button => button.addEventListener("click", () => setMode(button.dataset.view)));

  function baseNodes() {
    return data.nodes.filter(node => state.enabled.has(node.type));
  }
  function withDirectContext(candidates, anchors) {
    const candidateIDs = new Set(candidates.map(node => node.id)), anchorIDs = new Set(anchors.map(node => node.id)), visible = new Set(anchorIDs);
    data.links.forEach(link => {
      if (anchorIDs.has(link.from) && candidateIDs.has(link.to)) visible.add(link.to);
      if (anchorIDs.has(link.to) && candidateIDs.has(link.from)) visible.add(link.from);
    });
    return candidates.filter(node => visible.has(node.id));
  }
  function filteredNodes() {
    let candidates = baseNodes();
    const active = [["support", support.value], ["connectivity", connectivity.value], ["status", statusFilter.value]].filter(item => item[1]);
    active.forEach(([field, selected]) => {
      const anchors = candidates.filter(node => node[field] === selected);
      candidates = withDirectContext(candidates.filter(node => !node[field] || node[field] === selected), anchors);
    });
    const query = search.value.trim().toLowerCase();
    if (query) {
      const matches = candidates.filter(node => searchIndex.get(node.id).includes(query));
      candidates = withDirectContext(candidates, matches);
    }
    if (state.neighborhood && state.selected) {
      const selected = candidates.filter(node => node.id === state.selected);
      candidates = withDirectContext(candidates, selected);
    }
    return candidates;
  }

  function svgElement(name, attrs = {}) {
    const element = document.createElementNS("http://www.w3.org/2000/svg", name);
    Object.entries(attrs).forEach(([key, value]) => element.setAttribute(key, String(value)));
    return element;
  }
  function shorten(value, limit) { value = value || ""; return value.length > limit ? value.slice(0, limit - 1) + "…" : value; }
  function layout(nodes) {
    const positions = new Map(), rows = 10, cardW = 230, cardH = 66, colGap = 28, rowGap = 18, laneGap = 62;
    let laneX = 30;
    TYPES.forEach(([type, label]) => {
      const group = nodes.filter(node => node.type === type);
      if (!group.length) return;
      const columns = Math.ceil(group.length / rows);
      const lane = svgElement("text", {x: laneX, y: 24, class: "lane-label"}); lane.textContent = label.toUpperCase(); nodeLayer.append(lane);
      group.forEach((node, index) => {
        const column = Math.floor(index / rows), row = index % rows;
        positions.set(node.id, {x: laneX + column * (cardW + colGap), y: 46 + row * (cardH + rowGap), w: cardW, h: cardH});
      });
      laneX += columns * (cardW + colGap) + laneGap;
    });
    return positions;
  }

  function render() {
    edgeLayer.replaceChildren(); nodeLayer.replaceChildren();
    const nodes = filteredNodes(), visible = new Set(nodes.map(node => node.id));
    if (state.selected && !visible.has(state.selected)) { state.selected = ""; state.neighborhood = false; }
    if (!visible.has(state.focused)) state.focused = nodes.length ? nodes[0].id : "";
    state.positions = layout(nodes);
    const visibleLinks = data.links.filter(link => visible.has(link.from) && visible.has(link.to));
    const connected = new Set();
    if (state.selected) visibleLinks.forEach(link => { if (link.from === state.selected) connected.add(link.to); if (link.to === state.selected) connected.add(link.from); });
    visibleLinks.forEach(link => {
      const a = state.positions.get(link.from), b = state.positions.get(link.to); if (!a || !b) return;
      let d;
      if (b.x > a.x + a.w + 12) {
        const x1 = a.x + a.w, y1 = a.y + a.h / 2, x2 = b.x, y2 = b.y + b.h / 2, bend = Math.max(34, Math.abs(x2 - x1) * .42);
        d = "M" + x1 + "," + y1 + " C" + (x1 + bend) + "," + y1 + " " + (x2 - bend) + "," + y2 + " " + x2 + "," + y2;
      } else {
        const down = b.y >= a.y, x1 = a.x + a.w / 2, x2 = b.x + b.w / 2, y1 = down ? a.y + a.h : a.y, y2 = down ? b.y : b.y + b.h, bend = Math.max(28, Math.abs(y2 - y1) * .45), direction = down ? 1 : -1;
        d = "M" + x1 + "," + y1 + " C" + x1 + "," + (y1 + direction * bend) + " " + x2 + "," + (y2 - direction * bend) + " " + x2 + "," + y2;
      }
      const edge = svgElement("path", {d, class: "edge", "marker-end": "url(#arrow)"});
      if (state.selected && (link.from === state.selected || link.to === state.selected)) edge.classList.add("connected");
      const tip = svgElement("title"); tip.textContent = link.kind; edge.append(tip); edgeLayer.append(edge);
    });
    nodes.forEach((node, nodeIndex) => {
      const p = state.positions.get(node.id), group = svgElement("g", {transform: "translate(" + p.x + " " + p.y + ")", class: "node " + node.type, tabindex: state.focused === node.id ? "0" : "-1", role: "button", "aria-pressed": state.selected === node.id ? "true" : "false", "data-node-id": node.id, "aria-label": TYPE_LABEL[node.type] + ": " + node.title});
      if (state.selected === node.id) group.classList.add("selected"); else if (state.selected && !connected.has(node.id)) group.classList.add("dim");
      group.append(svgElement("rect", {class: "card", width: p.w, height: p.h}), svgElement("rect", {class: "stripe", width: 5, height: p.h, rx: 3}));
      const type = svgElement("text", {x: 15, y: 16, class: "type"}); type.textContent = TYPE_LABEL[node.type].toUpperCase();
      const title = svgElement("text", {x: 15, y: 38, class: "title"}); title.textContent = shorten(node.title || "Untitled", 31);
      const subtitle = svgElement("text", {x: 15, y: 55, class: "subtitle"}); subtitle.textContent = shorten(node.subtitle || node.status || node.support || "", 36);
      const tip = svgElement("title"); tip.textContent = node.title + (node.subtitle ? " — " + node.subtitle : ""); group.append(type, title, subtitle, tip);
      group.addEventListener("click", event => { event.stopPropagation(); selectNode(node.id); });
      group.addEventListener("keydown", event => {
        if (event.key === "Enter" || event.key === " ") { event.preventDefault(); selectNode(node.id); return; }
        let next = -1;
        if (event.key === "ArrowRight" || event.key === "ArrowDown") next = (nodeIndex + 1) % nodes.length;
        if (event.key === "ArrowLeft" || event.key === "ArrowUp") next = (nodeIndex - 1 + nodes.length) % nodes.length;
        if (event.key === "Home") next = 0; if (event.key === "End") next = nodes.length - 1;
        if (next >= 0) { event.preventDefault(); state.focused = nodes[next].id; state.refocus = true; render(); }
      });
      nodeLayer.append(group);
    });
    if (!nodes.length) { const empty = svgElement("text", {x: 40, y: 80, class: "empty"}); empty.textContent = "No nodes match the current view and filters."; nodeLayer.append(empty); }
    renderDetail(state.selected ? byID.get(state.selected) : null, visibleLinks);
    document.getElementById("focus-neighbors").disabled = !state.selected;
    document.getElementById("focus-neighbors").textContent = state.neighborhood ? "Show view" : "Focus neighbors";
    const modeLabel = state.mode === "custom" ? "Custom view" : document.querySelector("[data-view=" + state.mode + "]").textContent;
    document.getElementById("status-line").textContent = modeLabel + " · " + nodes.length + " of " + data.nodes.length + " rendered nodes · " + visibleLinks.length + " connections" + (state.neighborhood ? " · focused neighborhood" : "");
    applyTransform(); if (state.fit) { state.fit = false; fitGraph(); }
    if (state.refocus) { state.refocus = false; requestAnimationFrame(() => { const target = [...nodeLayer.querySelectorAll("[data-node-id]")].find(element => element.dataset.nodeId === state.focused); if (target) target.focus({preventScroll:true}); }); }
  }

  function selectNode(id) { state.focused = id; state.refocus = true; state.selected = state.selected === id ? "" : id; if (!state.selected) state.neighborhood = false; render(); }
  function renderDetail(node, visibleLinks) {
    const panel = document.getElementById("details-panel"), root = document.getElementById("detail"); root.replaceChildren();
    panel.classList.toggle("open", Boolean(node));
    if (!node) { const empty = document.createElement("p"); empty.className = "detail-empty"; empty.textContent = "Select a node to inspect its modeled fields and follow its connections."; root.append(empty); return; }
    const type = document.createElement("span"); type.className = "badge " + node.type; type.textContent = TYPE_LABEL[node.type];
    const title = document.createElement("h3"); title.className = "detail-title"; title.textContent = node.title; root.append(type, title);
    [["support", node.support], ["connectivity", node.connectivity], ["status", node.status]].forEach(([label, value]) => { if (!value) return; const badge = document.createElement("span"); badge.className = "badge " + node.type; badge.textContent = label + ": " + value; root.append(badge); });
    const controls = document.createElement("div"); controls.className = "detail-controls";
    const focus = document.createElement("button"); focus.type = "button"; focus.textContent = state.neighborhood ? "Show current view" : "Focus this neighborhood"; focus.addEventListener("click", () => { state.neighborhood = !state.neighborhood; state.fit = true; render(); }); controls.append(focus); root.append(controls);
    const list = document.createElement("dl"); list.className = "detail-list";
    (node.details || []).forEach(item => { const term = document.createElement("dt"), value = document.createElement("dd"); term.textContent = item.label; value.textContent = item.value; list.append(term, value); }); root.append(list);
    const related = visibleLinks.filter(link => link.from === node.id || link.to === node.id);
    if (related.length) {
      const heading = document.createElement("h2"); heading.textContent = "Connections (" + related.length + ")"; const connections = document.createElement("div"); connections.className = "connections";
      related.forEach(link => { const outgoing = link.from === node.id, otherID = outgoing ? link.to : link.from, other = byID.get(otherID); if (!other) return; const item = document.createElement("button"); item.type = "button"; item.className = "connection"; item.textContent = (outgoing ? "→ " : "← ") + link.kind + " · " + other.title; item.addEventListener("click", () => selectNode(otherID)); connections.append(item); });
      root.append(heading, connections);
    }
  }

  function applyTransform() { scene.setAttribute("transform", "translate(" + state.x + " " + state.y + ") scale(" + state.zoom + ")"); }
  function fitGraph() {
    const nodes = [...state.positions.values()]; if (!nodes.length) { state.zoom = 1; state.x = 35; state.y = 60; applyTransform(); return; }
    const minX = Math.min(...nodes.map(p => p.x)), minY = 0, maxX = Math.max(...nodes.map(p => p.x + p.w)), maxY = Math.max(...nodes.map(p => p.y + p.h));
    const rect = graph.getBoundingClientRect(), pad = 48; state.zoom = Math.max(MIN_ZOOM, Math.min(1.25, Math.min((rect.width - pad * 2) / Math.max(1, maxX - minX), (rect.height - pad * 2) / Math.max(1, maxY - minY)))); state.x = (rect.width - (maxX - minX) * state.zoom) / 2 - minX * state.zoom; state.y = (rect.height - (maxY - minY) * state.zoom) / 2 - minY * state.zoom; applyTransform();
  }
  function zoomAt(factor, clientX, clientY) { const rect = graph.getBoundingClientRect(), px = clientX - rect.left, py = clientY - rect.top, previous = state.zoom, next = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, previous * factor)); state.x = px - (px - state.x) * next / previous; state.y = py - (py - state.y) * next / previous; state.zoom = next; applyTransform(); }
  graph.addEventListener("wheel", event => { event.preventDefault(); zoomAt(event.deltaY < 0 ? 1.12 : .89, event.clientX, event.clientY); }, {passive:false});
  let dragging = false, lastX = 0, lastY = 0;
  graph.addEventListener("pointerdown", event => { if (event.target.closest("[data-node-id]")) return; dragging = true; lastX = event.clientX; lastY = event.clientY; graph.setPointerCapture(event.pointerId); });
  graph.addEventListener("pointermove", event => { if (!dragging) return; state.x += event.clientX - lastX; state.y += event.clientY - lastY; lastX = event.clientX; lastY = event.clientY; applyTransform(); });
  graph.addEventListener("pointerup", () => { dragging = false; }); graph.addEventListener("pointercancel", () => { dragging = false; });
  document.getElementById("fit").addEventListener("click", fitGraph);
  document.getElementById("zoom-in").addEventListener("click", () => { const rect = graph.getBoundingClientRect(); zoomAt(1.25, rect.left + rect.width / 2, rect.top + rect.height / 2); });
  document.getElementById("zoom-out").addEventListener("click", () => { const rect = graph.getBoundingClientRect(); zoomAt(.8, rect.left + rect.width / 2, rect.top + rect.height / 2); });
  document.getElementById("focus-neighbors").addEventListener("click", () => { if (!state.selected) return; state.neighborhood = !state.neighborhood; state.fit = true; render(); });
  document.getElementById("clear").addEventListener("click", () => { search.value = ""; support.value = ""; connectivity.value = ""; statusFilter.value = ""; state.selected = ""; setMode("overview"); });
  document.getElementById("detail-close").addEventListener("click", () => { state.selected = ""; state.neighborhood = false; render(); });
  let frame = 0; function scheduleRender() { cancelAnimationFrame(frame); frame = requestAnimationFrame(render); }
  [search, support, connectivity, statusFilter].forEach(control => control.addEventListener(control === search ? "input" : "change", () => { state.neighborhood = false; state.fit = true; scheduleRender(); }));
  window.addEventListener("resize", () => { state.fit = true; scheduleRender(); });
  renderReview(); updateViewControls(); render();
})();
</script>
</body>
</html>
`
