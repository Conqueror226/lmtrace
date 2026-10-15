'use strict';
(() => {
  // build_dashboard.py already ran both Python engines for every removal variant.
  // This object comes from generated dashboard-data.js (or its offline inline copy).
  const DATA = window.EVIDENCE_DATA;
  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const number = n => Number(n || 0).toLocaleString('en-US');
  const rank = {NONE:0, ARTIFACT:1, SESSION:2, ROUTE:3};
  const names = {SERVICE_INSTALL:'Service installation',SERVICE_CONTROL_ACCESS:'SCM pipe access',TASK_CREATE:'Scheduled task creation',WMI_EXECUTION:'WMI process creation',WINRM_SESSION:'PowerShell remoting host',DCOM_EXECUTION:'DCOM process creation',REMOTE_PROCESS:'Process creation'};
  const events = {4624:'Network logon',5145:'Share / pipe access',4697:'Service installation',4698:'Task creation',1:'Process creation',3:'Network connection'};
  const steps = [
    {name:'Collect',short:'Original records',eyebrow:'01 / RECORDED INPUT'},
    {name:'Observe',short:'Local artifact',eyebrow:'02 / WHAT HAPPENED'},
    {name:'Attribute',short:'Session identity',eyebrow:'03 / WHICH SESSION'},
    {name:'Corroborate',short:'Both endpoints',eyebrow:'04 / WHICH ROUTE'},
    {name:'Qualify',short:'Bounded conclusion',eyebrow:'05 / WHAT WE CAN SAY'}
  ];
  if (!DATA || DATA.schema_version !== 1) {
    $('stage-panel').innerHTML = '<h2>Dashboard data is unavailable.</h2><p>Run <code>python3 build_dashboard.py</code> in the project folder and reload this page.</p>';
    return;
  }
  // Track the selected recording, baseline observation, evidence variant, and UI state.
  // variant is an exact data key, e.g. 'baseline' or 'Sysmon 3 connection'.
  const state = {caseIndex:0, findingIndex:0, variant:'baseline', step:0, view:'flow', local:false, uploaded:null, record:null, exact:false};
  // Read the selected capture; changing the variant does not change this row.
  const row = () => DATA.rows[state.caseIndex];
  // Use the requested precomputed result if it exists; otherwise use baseline.
  // ?. safely returns undefined when a key is absent. The ternary chooses a value.
  const variant = () => row().variants[state.variant]?.result ? row().variants[state.variant] : row().variants.baseline;
  // The observation selector always indexes baseline, so removals can be compared
  // against the same original observation even when findings disappear or reorder.
  const baselineFinding = () => row().result.findings[state.findingIndex] || null;
  // Match display findings by target host (case-insensitive) and host-local logon ID.
  // This is UI alignment, not the engine's full identity/attribution validation.
  const sameSession = (a,b) => a && b && String(a.target_host).toLowerCase() === String(b.target_host).toLowerCase() && a.logon_id === b.logon_id;
  // Find the surviving counterpart of the selected baseline observation.
  function currentFinding() {
    // Start with the original observation selected by the user.
    const base = baselineFinding();
    // No baseline observation means there is nothing to align with a variant.
    if (!base) return null;
    // Read actual findings computed by Python for the current evidence choice.
    const findings = variant().result.findings;
    // Check whether a candidate shares at least one artifact source reference.
    const overlap = f => (f.artifact_refs || []).some(r => (base.artifact_refs || []).includes(r));
    // Prefer the same session, technique, and overlapping artifact evidence.
    return findings.find(f => sameSession(f,base) && f.technique === base.technique && overlap(f))
      // Otherwise allow a surviving related technique sharing an artifact.
      || findings.find(f => sameSession(f,base) && overlap(f))
      // Otherwise keep the same session and technique without requiring overlap.
      || findings.find(f => sameSession(f,base) && f.technique === base.technique)
      // Finally allow another finding in this session; report null if none survives.
      || findings.find(f => sameSession(f,base)) || null;
  }
  const badge = (level, label=level) => `<span class="tag ${esc(String(level).toLowerCase())}">${esc(label)}</span>`;
  const fact = (label, value, mono=false) => `<div class="fact"><span class="fact-label">${esc(label)}</span><span class="fact-value${mono?' mono':''}">${esc(value ?? 'Unavailable')}</span></div>`;
  const refShort = ref => `Line ${String(ref).split(':L').pop()}`;
  function referenceButton(ref, source=row().archive, label='') {
    return `<button class="record-link" data-ref="${esc(ref)}" data-source="${esc(source)}">${esc(label || refShort(ref))} ↗</button>`;
  }
  // Look up only the source records cited by the CURRENT computed finding.
  // The shared lookup also contains baseline-only records; their presence there
  // does not mean they still support a finding after evidence removal.
  function recordsFor(f) {
    // A missing finding has no supporting records to display.
    if (!f) return [];
    // Combine direct evidence references with any domain-alias evidence.
    const refs = [...(f.evidence || []).map(e=>e.ref), ...(f.alias_refs || [])];
    // Deduplicate references, resolve their records, and discard missing lookups.
    return [...new Set(refs)].map(ref => row().record_lookup[ref]).filter(Boolean);
  }
  // Choose which of those supporting records are relevant to the visible step.
  function focusRecords(f) {
    // Begin with the current finding's citations, not every event in the lookup.
    const records = recordsFor(f);
    // For Observe, show only records listed as artifacts.
    if (state.step === 1) return records.filter(r=>(f.artifact_refs || []).includes(r.ref));
    // For Attribute, show logons, artifact records, and identity-alias evidence.
    if (state.step === 2) return records.filter(r=>String(r.event_id)==='4624' || (f.artifact_refs || []).includes(r.ref) || (f.alias_refs || []).includes(r.ref));
    // For Corroborate, show cited connection/logon records; removed connections are absent.
    if (state.step === 3) return records.filter(r=>String(r.event_id)==='3' || String(r.event_id)==='4624');
    // For the remaining steps, show all citations of the current finding.
    return records;
  }
  // Choose a useful baseline observation when opening a recording.
  function pickDefaultFinding() {
    // Read this recording's full-data findings.
    const findings = row().result.findings;
    // Prefer its expected exercise category supported at SESSION or ROUTE level.
    const preferred = findings.findIndex(f=>f.technique===row().expected && rank[f.level]>=2);
    // Use that position when found; otherwise use the first observation.
    state.findingIndex = preferred>=0 ? preferred : 0;
  }
  // Open a recording with a requested variant, usually the full-data baseline.
  function setCase(index, v='baseline') {
    // Clamp the requested recording index to the available range.
    state.caseIndex = Math.max(0,Math.min(DATA.rows.length-1,index));
    // Reject a variant without a computed result, such as an absent event type.
    state.variant = row().variants[v]?.result ? v : 'baseline';
    // Select a baseline observation to follow through this removal experiment.
    pickDefaultFinding();
    // Draw the recording and its selected precomputed result.
    renderFlow();
  }
  function initialize() {
    const s = DATA.summary;
    $('metrics').innerHTML = [
      [number(s.recordings),'Recorded captures','6 exercise categories'],
      [number(s.records),'Windows events','Original inputs, hash checked'],
      [`${s.expected_observed}<em> / ${s.recordings}</em>`,'Expected categories observed','1 explained coverage gap'],
      [`${s.ablation_monotonic}<em> / ${s.ablation_runs}</em>`,'Removal checks passed','Whole event types withheld']
    ].map(([value,label,sub])=>`<div class="metric"><div class="metric-value">${value}</div><div class="metric-label"><strong>${esc(label)}</strong>${esc(sub)}</div></div>`).join('');
    $('case-select').innerHTML = DATA.rows.map((r,i)=>`<option value="${i}">${esc(r.title)}</option>`).join('');
    // Build the evidence selector using the same names as Python's ABLATIONS.
    // The option VALUE is 'Sysmon 3 connection'; only its label adds 'Remove '.
    $('variant-select').innerHTML = '<option value="baseline">Baseline · all records</option>' + DATA.ablations.map(a=>`<option value="${esc(a)}">Remove ${esc(a)}</option>`).join('');
    const unique = [...new Set(DATA.rows.map(r=>r.expected))];
    $('filter-technique').innerHTML += unique.map(t=>`<option value="${esc(t)}">${esc(names[t])}</option>`).join('');
    $('revision-label').textContent = `OTRF / Security-Datasets · revision ${DATA.revision.slice(0,12)}`;
    $('experiment-count').textContent = `${s.ablation_runs} computed removals`;
    renderMatrix();
    pickDefaultFinding();
    navigate();
    if (location.protocol !== 'file:') {
      fetch('api/mode',{cache:'no-store'}).then(r=>r.ok?r.json():null).then(mode=>{
        state.local=!!mode?.local_analysis;
        $('mode-label').textContent=state.local?'Local Python engine':'Recorded demo';
        if(state.local){$('download-project').textContent='Local project ready · no pip';$('download-project').disabled=true;}
        renderAnalyze();
      }).catch(()=>renderAnalyze());
    } else { $('download-project').textContent='Standalone · works offline';$('download-project').disabled=true;renderAnalyze(); }
  }
  // Refresh the flow after a recording, observation, variant, or step changes.
  function renderFlow() {
    // Read the capture, saved variant, surviving finding, and baseline comparison.
    const r = row(), v = variant(), f = currentFinding(), base = baselineFinding();
    // Synchronize the recording selector with state.
    $('case-select').value = String(state.caseIndex);
    // Build observation options from baseline, preserving a stable comparison point.
    $('finding-select').innerHTML = r.result.findings.length ? r.result.findings.map((item,i)=>`<option value="${i}">${esc(names[item.technique] || item.technique)} · ${esc(item.logon_id || 'no session')}</option>`).join('') : '<option value="0">No supported observation</option>';
    // Keep the chosen baseline observation selected.
    $('finding-select').value = String(state.findingIndex);
    // Disable observation selection when baseline has no findings.
    $('finding-select').disabled = !r.result.findings.length;
    // Update removal-option availability for the current recording.
    for (const option of $('variant-select').options) {
      // Disable absent event types; baseline is always available.
      if (option.value !== 'baseline') option.disabled = !r.variants[option.value]?.removed;
    }
    // Show the evidence choice currently stored in state.
    $('variant-select').value = state.variant;
    // Show the removed count and warn if the original technique no longer survives.
    $('experiment-note').innerHTML = state.variant !== 'baseline' ? `<div class="notice"><span aria-hidden="true">−</span><div class="grow"><strong>${esc(state.variant)} withheld.</strong> ${number(v.removed)} records removed from the full capture. The remaining records were analyzed again by both Python engines.${base&&(!f||f.technique!==base.technique)?`<br>The selected ${esc(names[base.technique])} claim no longer survives; ${f?esc(names[f.technique])+' remains in this session.':'no related finding remains.'}`:''}</div><button class="secondary" data-action="reset">Restore baseline</button></div>` : '';
    // Mark stages available from the saved finding: artifact, session rank, and route.
    const availability = [true,!!f,rank[f?.level]>=2,!!f?.route,true];
    // Render the five stage buttons with unavailable evidence visibly marked.
    $('flow-steps').innerHTML = steps.map((s,i)=>`<button class="step ${i===state.step?'active':''} ${availability[i]?'':'missing'}" data-step="${i}" aria-pressed="${i===state.step}"><span class="step-number">${i+1}</span><strong>${s.name}</strong><small>${availability[i]?esc(s.short):'Evidence unavailable'}</small></button>`).join('');
    // Draw the active stage using this finding, including its route gap if any.
    renderStage(f);
    // Display the finding level and its bounded claim.
    renderConclusion(f);
    // Display only the current finding citations relevant to the active step.
    renderEvidence(f);
    // Display quality and gaps from this variant, not the baseline result.
    renderQuality(v.result);
    // Prevent moving before the first stage.
    $('previous-step').disabled=state.step===0;
    // Prevent moving beyond the last stage.
    $('next-step').disabled=state.step===4;
    // Use a completion label on the last stage.
    $('next-step').textContent=state.step===4?'Flow complete ✓':'Next step →';
    // Update the displayed stage number and description.
    $('step-caption').textContent=`Step ${state.step+1} of 5 · ${steps[state.step].short}`;
  }
  function stageShell(title, description, content, status, note='') {
    $('stage-panel').innerHTML = `<p class="eyebrow">${steps[state.step].eyebrow}</p><div class="stage-title-row"><h2>${esc(title)}</h2>${status || ''}</div><p class="stage-description">${esc(description)}</p>${content}${note?`<p class="stage-footnote">${esc(note)}</p>`:''}`;
  }
  function renderStage(f) {
    const r=row(), v=variant();
    const all=recordsFor(f), artifact=all.find(e=>(f?.artifact_refs||[]).includes(e.ref)), logon=all.find(e=>String(e.event_id)==='4624');
    const fields=artifact?.fields||{}, login=logon?.fields||{};
    if (state.step===0) {
      stageShell('Start with the original capture.','The engines consume Windows event records, not the exercise name. Every cited observation keeps a file, line number, and hash back to its source.',
        `<div class="fact-grid">${fact('Capture',r.dataset_id)}${fact('Available records',number(v.result.counts.records))}${fact('Publisher',DATA.publisher)}${fact('Source revision',DATA.revision.slice(0,12),true)}</div><p class="muted">${esc(DATA.data_kind)}</p><p>${r.source?.url?`<a class="text-button" href="${esc(r.source.url)}" target="_blank" rel="noopener">Open the pinned original ZIP ↗</a>`:''}</p>`,badge('ROUTE','HASH-VERIFIED INPUT'),
        'Only referenced source records are embedded in this page. The offline project includes the full captures and engines.');
    } else if (state.step===1) {
      if (!f) {
        stageShell('No supported local observation.','The engine does not invent an artifact from the published exercise label.',
          `<div class="notice"><div>${esc(r.known_limit || 'The retained records do not support a finding for the selected baseline observation.')}</div></div>`,badge('NONE','NOT OBSERVED'),
          'Not observed means this contract could not establish the behavior from these records; it does not mean the exercise did not occur.');
        return;
      }
      const titles={SERVICE_INSTALL:'A service was registered.',SERVICE_CONTROL_ACCESS:'The SCM pipe was accessed.',TASK_CREATE:'A scheduled task was registered.',WMI_EXECUTION:'A WMI-hosted process was created.',WINRM_SESSION:'A remoting host process started.',DCOM_EXECUTION:'A DCOM-launched process was created.',REMOTE_PROCESS:'A process was created.'};
      let details='';
      if(f.technique==='SERVICE_INSTALL') details=fact('Service name',fields.ServiceName)+fact('Registered binary',fields.ServiceFileName,true)+fact('Service run-as',fields.ServiceAccount)+fact('Artifact record',artifact?`${artifact.channel} · Event ${artifact.event_id} · line ${artifact.line}`:null);
      else if(f.technique==='TASK_CREATE') details=fact('Task name',fields.TaskName,true)+fact('Artifact record',artifact?`${artifact.channel} · Event ${artifact.event_id} · line ${artifact.line}`:null);
      else if(f.technique==='SERVICE_CONTROL_ACCESS') details=fact('Share / pipe',`${fields.ShareName||'IPC$'} / ${fields.RelativeTargetName||'svcctl'}`,true)+fact('Artifact record',artifact?`${artifact.channel} · Event ${artifact.event_id} · line ${artifact.line}`:null);
      else details=fact('Image',fields.Image,true)+fact('Parent image',fields.ParentImage,true)+fact('Command line',fields.CommandLine,true)+fact('Artifact record',artifact?`${artifact.channel} · Event ${artifact.event_id} · line ${artifact.line}`:null);
      stageShell(titles[f.technique]||'An action was recorded.','This is the smallest supported claim: a concrete action on the target. Remote attribution is evaluated separately.',
        `<div class="fact-grid">${fact('Observed target',f.target_host)}${fact('Observed category',names[f.technique]||f.technique)}${details}</div>`,badge('ARTIFACT','LOCAL OBSERVATION'),
        f.technique==='SERVICE_INSTALL'||f.technique==='TASK_CREATE'?'Registration is not proof that the service or task executed.':'The mechanism label comes from recorded fields; it is not a malicious-intent label.');
    } else if(state.step===2) {
      if(!f || rank[f.level]<2 || !logon) {
        stageShell('The remote session is unproven.','An artifact alone cannot establish which remote network-logon session owns it.',
          `<div class="notice"><div>${esc((f?.notes||[]).join(' ') || 'No usable, unambiguous 4624 network logon can be joined to this observation in the retained evidence.')}</div></div>${f?`<div class="fact-grid">${fact('Artifact target',f.target_host)}${fact('Artifact logon ID',f.logon_id,true)}</div>`:''}`,badge('ARTIFACT','ATTRIBUTION UNAVAILABLE'),
          'A logon ID is host-local. The engine also checks the principal and same-host ordering; nearby timestamps alone cannot create this link.');
        return;
      }
      const sid=fields.SubjectUserSid||fields.UserSid||'Not recorded on this process event';
      const artifactLogon=fields.SubjectLogonId||fields.LogonId||f.logon_id;
      const artAccount=fields.SubjectUserName || fields.User || f.account;
      const agreement=(label,a,b)=>`<div class="agreement-row"><span>${esc(label)}</span><span class="mono">${esc(a ?? 'Unavailable')}</span><span class="mono">${esc(b ?? 'Unavailable')}</span></div>`;
      stageShell('The artifact belongs to this session.',fields.SubjectUserSid?'A successful network logon on the same target provides the session anchor. The SID, account and logon ID agree with the action record.':'A successful network logon anchors the process by host, logon ID and domain-qualified account. This process event does not carry a SID; domain aliases require separate Security evidence.',
        `<div class="agreement-table"><div class="agreement-row heading"><span>JOIN KEY</span><span>NETWORK LOGON · 4624</span><span>ACTION / PRINCIPAL</span></div>${agreement('Host',logon.host,f.target_host)}${agreement('Logon ID',login.TargetLogonId,artifactLogon)}${agreement('SID',login.TargetUserSid,sid)}${agreement('Account',`${login.TargetDomainName||''}\\${login.TargetUserName||''}`,artAccount)}</div><div class="fact-grid">${fact('Authentication',f.authentication)}${fact('Session',f.logon_id,true)}</div>${(f.alias_refs||[]).length?`<p class="muted">Domain aliases are supported by ${(f.alias_refs||[]).length} successful Security record(s) for this SID; these are included below.</p>`:''}`,badge('SESSION','SESSION ATTRIBUTED'),
        'Security joins check success, usable identifiers, same-host event ordering and a 60-second window. Process joins use a 120-second collection-time gate.');
    } else if(state.step===3) {
      // Python returns route: null when retained evidence cannot corroborate a route.
      // Remove Sysmon 3 reaches this branch for the SharpSC Create example.
      if(!f?.route) {
        stageShell('The route is not corroborated.','Naming a remote source host requires a matching TCP connection observed on both endpoints, not an IP address seen in one record.',
          `<div class="notice"><div>${esc(f?.route_gap || 'The retained evidence does not contain a unique, usable two-sided connection for this session.')}</div></div>${f?`<div class="fact-grid">${fact('Supported level',f.level)}${fact('Target',f.target_host)}</div>`:''}`,badge(f?.level||'NONE','NO TWO-SIDED ROUTE'),
          'A session claim can survive without a route. No multi-hop path or first pivot is inferred.');
        return;
      }
      const route=f.route;
      const outbound=row().record_lookup[route.outbound.ref], inbound=row().record_lookup[route.inbound.ref];
      const pair=(label,a,b)=>`<div class="agreement-row"><span>${esc(label)}</span><span class="mono">${esc(a)}</span><span class="mono">${esc(b)}</span></div>`;
      stageShell('Both hosts recorded the same connection.','The session source endpoint agrees with one outbound and one inbound Sysmon TCP event. Hosts, addresses, ports and direction are all checked.',
        `<div class="relation"><div><span class="node-label">SOURCE HOST</span><div class="node-name">${esc(route.source_host)}</div><span class="node-endpoint mono">${esc(route.source_ip)}:${esc(route.source_port)}</span></div><span class="join-arrow" aria-label="to">→</span><div><span class="node-label">TARGET HOST</span><div class="node-name">${esc(route.target_host)}</div><span class="node-endpoint mono">${esc(route.target_ip)}:${esc(route.target_port)}</span></div></div><div class="agreement-table"><div class="agreement-row heading"><span>FIELD</span><span>SOURCE RECORD</span><span>TARGET RECORD</span></div>${pair('Source',`${outbound?.fields.SourceIp}:${outbound?.fields.SourcePort}`,`${inbound?.fields.SourceIp}:${inbound?.fields.SourcePort}`)}${pair('Target',`${outbound?.fields.DestinationIp}:${outbound?.fields.DestinationPort}`,`${inbound?.fields.DestinationIp}:${inbound?.fields.DestinationPort}`)}${pair('Initiated',outbound?.fields.Initiated,inbound?.fields.Initiated)}</div>`,badge('ROUTE','ENDPOINTS CORROBORATED'),
        'The 10-second flow gate uses collection time. It is a matching constraint, not a cross-host causal clock or proof of command execution.');
    } else {
      const text=claimText(f);
      stageShell('Say only what the evidence supports.','The output carries its technique, evidence level and limitations together. The same contract can return a weaker claim when evidence is missing.',
        `<div class="notice"><div><strong>${esc(text)}</strong></div></div><div class="fact-grid">${fact('Authorization','Unknown · no change-approval or policy source')}${fact('Intent','Not inferred from these records')}${fact('Path scope','One independently attributed session')}${fact('Execution boundary',f?.technique==='SERVICE_INSTALL'?'Service registration; execution unproven':f?.technique==='TASK_CREATE'?'Task registration; execution unproven':'Only the recorded behavior is asserted')}</div>`,badge(f?.level||'NONE',f?.level||'NO SUPPORTED CLAIM'),
        'Next, remove an event type using “Evidence available” above. Every alternate result was recomputed by the Python engines over the retained original records.');
    }
  }
  // Turn the saved finding into wording; this function never assigns its level.
  function claimText(f) {
    if(!f) return 'No supported claim for the selected observation in the available evidence.';
    const what=names[f.technique] || f.technique;
    if(f.level==='ROUTE') return `${what} on ${f.target_host}, linked to session ${f.logon_id} with the route from ${f.route.source_host} corroborated on both hosts.`;
    // Retain session attribution while explicitly stating that its route is uncorroborated.
    if(f.level==='SESSION') return `${what} on ${f.target_host}, linked to network-logon session ${f.logon_id}; the source route is uncorroborated.`;
    return `${what} observed on ${f.target_host}; remote-session attribution is unavailable.`;
  }
  function renderConclusion(f) {
    const base=baselineFinding();
    const applicable=base&&['SERVICE_INSTALL','SERVICE_CONTROL_ACCESS'].includes(base.technique);
    const observations=variant().strict.observations;
    const strict=applicable?observations.find(o=>String(o.route?.target_host).toLowerCase()===String(base.target_host).toLowerCase()&&o.identity?.logon_id===base.logon_id):null;
    $('conclusion-panel').innerHTML = `<p class="eyebrow">CURRENT ENGINE CONCLUSION</p>${badge(f?.level||'NONE')}<h3>${f?esc(names[f.technique]||f.technique):'Selected claim unavailable'}</h3><p class="conclusion-text">${esc(claimText(f))}</p><ul class="boundary-list"><li><strong>Authorization · unknown</strong>No policy or change-approval evidence.</li><li><strong>Intent · not inferred</strong>Observed behavior does not establish malicious intent.</li><li><strong>Scope · this session</strong>No first-pivot or multi-hop path claim.</li></ul>${applicable?`<div class="contract-note"><strong>Strict SCM contract</strong><br>${esc(strict?strict.status.replaceAll('_',' '):'No supported SCM observation in this session.')}<br>Also requires session-attributed svcctl access. It can fail while the general artifact/session contract still holds.</div>`:''}`;
  }
  function renderEvidence(f) {
    const records=focusRecords(f);
    $('evidence-heading').textContent=state.step===0?'Trace back to source records':'Records behind this step';
    $('evidence-note').textContent=records.length?`${records.length} cited records · Collection time is shown for inspection, not causal ordering. Open a line to inspect its full contents and hash.`:'No supporting records for this step in the selected observation. The missing evidence is part of the result.';
    $('evidence-table').innerHTML=records.length?`<table><thead><tr><th>EVENT / ROLE</th><th>RECORDED ON</th><th>COLLECTED AT (UTC)</th><th>SOURCE REFERENCE</th></tr></thead><tbody>${records.map(r=>`<tr><td><span class="mono">${esc(r.event_id)}</span><span class="event-label">${esc(events[r.event_id]||'Identity / supporting event')}</span></td><td class="cell-host">${esc(r.host)}<br><span class="muted">${esc(r.channel)}</span></td><td class="cell-time">${esc(r.collected_at_utc||'Unavailable')}</td><td>${referenceButton(r.ref)}<br><span class="muted mono">${esc(r.record_number==null?'No record number':`Record ${r.record_number}`)}</span></td></tr>`).join('')}</tbody></table>`:'<div class="empty">A gap is shown explicitly. No record is substituted to complete the flow.</div>';
  }
  function renderQuality(result) {
    const q=result.quality || {}, rejects=Object.values(q.unusable_identifiers||{}).reduce((a,b)=>a+Number(b),0);
    const entries=[...(result.gaps||[]),...(result.conflicts||[]),...(q.rejected_examples||[])];
    $('quality-panel').innerHTML=`<details><summary>Coverage &amp; data quality · ${number(q.conflicting_event_identities)} conflicting identities · ${number(rejects)} identifier rejections · ${number(result.gaps?.length)} gaps</summary><p>${esc(q.screening?.note||'No screening summary available.')}</p><p>${number(q.flow_records_unusable_for_routes)} flow records could not supply usable route fields. Unusable records are not treated as negative evidence.</p>${entries.length?`<ul>${entries.slice(0,20).map(e=>`<li>${esc(e.reason||e.message||JSON.stringify(e))}</li>`).join('')}</ul>`:''}<p>Some examples are capped for readability; the downloaded analysis JSON retains the engine result. ${esc(DATA.evaluation_limit)}</p></details>`;
  }
  function renderLibrary() {
    const query=$('search-recordings').value.toLowerCase(),tech=$('filter-technique').value;
    const rows=DATA.rows.map((r,i)=>({...r,index:i})).filter(r=>(!tech||r.expected===tech)&&[r.title,r.dataset_id,r.expected_label].join(' ').toLowerCase().includes(query));
    $('library-count').textContent=`${rows.length} of ${DATA.rows.length} recordings`;
    $('recording-grid').innerHTML=rows.length?rows.map(r=>`<article class="panel recording-card"><div class="card-top"><span class="dataset-id mono">${esc(r.dataset_id)}</span>${badge(r.level)}</div><h3>${esc(r.title)}</h3><p>${esc(r.expected_label)}</p><div class="outcome ${r.outcome==='NOT_OBSERVED'?'missing':''}">${r.outcome==='OBSERVED'?'✓ Expected category observed':r.outcome==='NOT_OBSERVED'?'! Expected category not observed':'Additional remote category'}</div><div class="card-bottom"><span>${number(r.result.counts.records)} records · ${r.result.findings.length} findings</span><button class="text-button" data-case="${r.index}">Explore flow →</button></div></article>`).join(''):'<div class="empty">No recordings match these filters.</div>';
  }
  function renderMatrix() {
    $('experiment-matrix').innerHTML=`<table class="matrix"><thead><tr><th>RECORDING</th><th>BASELINE</th>${DATA.ablations.map(a=>`<th>REMOVE<br>${esc(a)}</th>`).join('')}</tr></thead><tbody>${DATA.rows.map((r,i)=>`<tr><td>${esc(r.title)}<small>${esc(r.expected_label)}</small></td><td><button class="${r.level.toLowerCase()}" data-case="${i}" data-variant="baseline">${esc(r.level)}</button></td>${DATA.ablations.map(a=>{const c=r.variants[a];return `<td>${c.removed?`<button class="${c.level.toLowerCase()}" data-case="${i}" data-variant="${esc(a)}" title="${esc(a)}: ${c.removed} records removed; ${esc(c.result.remote_techniques.map(t=>names[t]).join(', ')||'no remote category')}">${esc(c.level)}</button>`:'<span aria-label="Event type absent">—</span>'}</td>`}).join('')}</tr>`).join('')}</tbody></table>`;
  }
  function navigate() {
    const raw=location.hash.slice(1).split('/');
    const view=['flow','recordings','experiments','analyze'].includes(raw[0])?raw[0]:'flow';
    state.view=view;
    if(view==='flow' && raw[1]) {
      const idx=DATA.rows.findIndex(r=>r.archive===decodeURIComponent(raw[1]));
      if(idx>=0) setCase(idx,raw[2]?decodeURIComponent(raw[2]):'baseline');
    }
    document.querySelectorAll('.view').forEach(el=>el.hidden=el.id!==`view-${view}`);
    document.querySelectorAll('[data-view]').forEach(el=>{el.classList.toggle('active',el.dataset.view===view);if(el.dataset.view===view)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current')});
    const titles={flow:['Follow the evidence.','An event shows what happened. A defensible remote-activity claim shows how the records agree.'],recordings:['Explore the recordings.','Fourteen original captures, six exercise categories, and one visible, explained coverage gap.'],experiments:['Test what survives.','Remove a whole event type and inspect the claims that the retained evidence can still support.'],analyze:['Bring your own evidence.','Use the same Python engines to turn a Windows event capture into inspectable, qualified findings.']};
    $('page-title').textContent=titles[view][0];$('page-lead').textContent=titles[view][1];
    if(view==='flow')renderFlow();if(view==='recordings')renderLibrary();if(view==='analyze')renderAnalyze();
  }
  function goFlow(index, v='baseline') {
    state.step=v==='baseline'?0:4;
    setCase(index,v);
    const hash=`#flow/${row().archive}/${encodeURIComponent(state.variant)}`;
    if(location.hash===hash)navigate();else location.hash=hash;
    $('main').focus({preventScroll:true});
    window.scrollTo({top:0,behavior:'instant'});
  }
  function renderAnalyze() {
    $('local-analysis').hidden=!state.local;
    $('hosted-analysis-note').hidden=state.local;
  }
  async function analyzeFile(file) {
    if(!state.local || !file)return;
    if(file.size>100*1024*1024){$('upload-status').textContent='The limit is 100 MB. Choose a smaller capture.';return;}
    $('capture-file').disabled=true;
    $('upload-status').textContent=`Analyzing ${file.name} with both Python engines…`;
    $('upload-result').innerHTML='';
    try {
      const response=await fetch('api/analyze',{method:'POST',headers:{'X-Filename':encodeURIComponent(file.name)},body:file});
      const data=await response.json();if(!response.ok)throw new Error(data.error||'Analysis failed.');
      state.uploaded=data;
      $('upload-status').textContent=`${data.name} · ${number(data.records)} parsed records · analysis complete`;
      $('upload-result').innerHTML=`<div class="panel information"><h2>${data.result.findings.length} supported findings</h2><p>General categories: ${esc(data.result.remote_techniques.map(t=>names[t]||t).join(', ')||'none remotely attributed')}.</p><p>Strict SCM contract: <strong>${esc(data.strict.status)}</strong>. This contract evaluates service-control access and installation; it is not a score for WMI, remoting or DCOM.</p><p>Parse issues: ${esc(JSON.stringify(data.integrity.issues))}</p><button class="secondary" data-action="download-upload">Download analysis JSON ↓</button></div><div class="upload-findings">${data.result.findings.map(f=>`<article class="panel upload-finding">${badge(f.level)}<h3>${esc(names[f.technique]||f.technique)}</h3><p>${esc(claimText(f))}</p><p>${esc((f.notes||[]).join(' '))}</p><div class="reference-list">${[...new Set([...(f.evidence||[]).map(e=>e.ref),...(f.alias_refs||[])])].map(ref=>referenceButton(ref,'upload')).join('')}</div></article>`).join('')||'<p class="empty">No supported findings. Review the downloaded gaps and data-quality notes.</p>'}</div>`;
    } catch(error){$('upload-status').textContent=`Could not analyze capture: ${error.message}`;}
    finally{$('capture-file').disabled=false;$('capture-file').value='';}
  }
  function downloadText(name,text,type='application/json') {
    const url=URL.createObjectURL(new Blob([text],{type}));
    const a=document.createElement('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),5000);
  }
  function downloadProject() {
    if(state.local||location.protocol==='file:') {
      if(state.local)downloadText('START_HERE.txt','You are already running the downloaded local project.\nStart: python3 dashboard.py\nStandalone: dashboard-offline.html\nRebuild: python3 build_dashboard.py\nTests: python3 -m unittest discover -v\n','text/plain');
      else { $('hosted-analysis-note').hidden=false; location.hash='#analyze'; }
      return;
    }
    const a=document.createElement('a');a.href='downloads/Soliton_Evidence_Dashboard.zip';a.download='Soliton_Evidence_Dashboard.zip';a.click();
  }
  async function openRecord(source,ref) {
    $('record-verification').textContent='';
    let record=DATA.rows.find(r=>r.archive===source)?.record_lookup[ref];
    if(!record&&state.local) {
      try{const response=await fetch(`api/record?source=${encodeURIComponent(source)}&ref=${encodeURIComponent(ref)}`);record=await response.json();if(!response.ok)throw new Error(record.error);}catch(error){record={ref,json:`Record unavailable: ${error.message}`,sha256:''};}
    }
    if(!record)record={ref,json:'This reference was not included in the exported record subset.',sha256:''};
    state.record=record;state.exact=false;
    $('record-title').textContent=`${events[record.event_id]||'Original Windows event'}${record.event_id!=null?' · '+record.event_id:''}`;
    $('record-ref').textContent=ref;
    $('record-hash').textContent=record.sha256||record.record_sha256||'Unavailable';
    $('record-facts').innerHTML=[fact('Recorded on',record.host),fact('Channel',record.channel),fact('Record number',record.record_number),fact('Collection time (UTC)',record.collected_at_utc)].join('');
    $('record-format').disabled=!record.raw_line;
    $('record-save').disabled=!record.raw_line;
    $('record-format').textContent='Show exact source line';
    $('record-json').textContent=record.json;
    $('record-dialog').showModal();
    if(record.raw_line && window.crypto?.subtle) {
      try{const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(record.raw_line));const hash=[...new Uint8Array(digest)].map(b=>b.toString(16).padStart(2,'0')).join('');if(state.record===record)$('record-verification').textContent=hash===(record.sha256||record.record_sha256)?'✓ Original line hash verified':'Hash mismatch — inspect the source export';}catch{if(state.record===record)$('record-verification').textContent='Hash was checked by the Python exporter.';}
    } else if(record.raw_line)$('record-verification').textContent='Hash checked by Python at export.';
  }
  document.addEventListener('click',event=>{
    const target=event.target.closest('button');if(!target)return;
    if(target.dataset.step!=null){state.step=Number(target.dataset.step);renderFlow();}
    if(target.dataset.case!=null)goFlow(Number(target.dataset.case),target.dataset.variant||'baseline');
    if(target.dataset.ref)openRecord(target.dataset.source,target.dataset.ref);
    if(target.dataset.action==='reset'){state.variant='baseline';history.replaceState(null,'',`#flow/${row().archive}/baseline`);renderFlow();}
    if(target.dataset.action==='download-upload'&&state.uploaded)downloadText('capture-analysis.json',JSON.stringify(state.uploaded,null,2));
  });
  $('case-select').addEventListener('change',()=>{state.step=0;goFlow(Number($('case-select').value));});
  $('finding-select').addEventListener('change',()=>{state.findingIndex=Number($('finding-select').value);renderFlow();});
  // Run this handler when the user changes the Evidence available dropdown.
  $('variant-select').addEventListener('change',()=>{
    // Save the option's data key, e.g. 'Sysmon 3 connection' (without 'Remove ').
    state.variant=$('variant-select').value;
    // Update the URL fragment so the recording/variant can be reopened by link.
    // replaceState changes history without reloading the page or firing hashchange.
    history.replaceState(null,'',`#flow/${row().archive}/${encodeURIComponent(state.variant)}`);
    // Read the precomputed variant and repaint the current stage and conclusion.
    // No Python call, API request, or event removal happens in this handler.
    renderFlow();
  });
  $('previous-step').addEventListener('click',()=>{state.step=Math.max(0,state.step-1);renderFlow();});
  $('next-step').addEventListener('click',()=>{state.step=Math.min(4,state.step+1);renderFlow();});
  $('search-recordings').addEventListener('input',renderLibrary);
  $('filter-technique').addEventListener('change',renderLibrary);
  $('present-button').addEventListener('click',()=>{const active=document.body.classList.toggle('presenting');$('present-button').setAttribute('aria-pressed',String(active));$('present-button').textContent=active?'Exit presentation ✕':'Presentation view ↗';});
  $('export-result').addEventListener('click',()=>downloadText(`${row().dataset_id}-${state.variant==='baseline'?'baseline':'removal'}-analysis.json`,JSON.stringify({dataset:row().dataset_id,experiment:state.variant,engine_sha256:DATA.engine_sha256,source:row().source,...variant()},null,2)));
  $('download-project').addEventListener('click',downloadProject);$('download-local').addEventListener('click',downloadProject);
  $('capture-file').addEventListener('change',()=>analyzeFile($('capture-file').files[0]));
  for(const name of ['dragover','dragleave','drop'])$('drop-zone').addEventListener(name,event=>{event.preventDefault();$('drop-zone').classList.toggle('dragover',name==='dragover');if(name==='drop')analyzeFile(event.dataTransfer.files[0]);});
  $('record-close').addEventListener('click',()=>$('record-dialog').close());
  $('record-dialog').addEventListener('click',event=>{if(event.target===$('record-dialog')){const r=$('record-dialog').getBoundingClientRect();if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)$('record-dialog').close();}});
  $('record-format').addEventListener('click',()=>{state.exact=!state.exact;$('record-json').textContent=state.exact?state.record.raw_line:state.record.json;$('record-format').textContent=state.exact?'Show formatted JSON':'Show exact source line';});
  $('record-save').addEventListener('click',()=>downloadText(`event-line-${String(state.record.ref).split(':L').pop()}.ndjson`,state.record.raw_line,'application/x-ndjson'));
  window.addEventListener('hashchange',navigate);
  initialize();
})();
