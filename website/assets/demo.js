'use strict';

// Public, local examples only. These controls never call the hosted service.
//
// Copy lives in D2 below and must stay in sync with the matching d2.* keys
// in assets/locales/*.json — website/check.py enforces it. Static panel
// markup ships English with data-i18n hooks; dynamic parts render from D2
// for the current language and re-render on `waypost:lang`.
(() => {
  const controls = [...document.querySelectorAll('[data-preview]')];
  if (!controls.length) return;

  const D2 = {
  "en": {
    "tabsLabel": "Try inbox, assistants and libraries",
    "owner": "Trip plan · sample space",
    "agentsH": "Who hands results to you?",
    "agentsSub": "Roles and connections example",
    "roleIntroHtml": "<p><strong>Primary assistants</strong> are the ones you mainly talk to: they summarize and report to you. <strong>Connected assistants</strong> deliver their own results.</p><p>The primary can be an assistant you use now. Laixin plans to join; switch roles here to preview.</p>",
    "tryPrimary": "Try switching the sample primary",
    "optCustom": "Your everyday assistant",
    "optLaixin": "Laixin (planned)",
    "laixinName": "Laixin",
    "laixinPlan": "This page only demonstrates the role; Laixin integration is still planned.",
    "primaryAvatar": "P",
    "filePrefsSmall": "Your confirmed picks · budget & dietary",
    "prefsActor": "You",
    "primaryNoteDefault": "Choosing a primary sets a suggested default recipient for new connections. Automatic collection requires a host schedule or bridge; existing connections stay unchanged.",
    "primaryNoteTpl": "Showing new connections sending to “{primary}”. Automatic collection requires a host schedule or bridge; existing connections and delivered content stay unchanged.",
    "primaryNoteTplLaixin": "Showing new connections sending to “{primary}”. Laixin integration is planned. Automatic collection requires host scheduling or a bridge.",
    "agentPrimarySmall": "Primary · summarizes results, reports to you",
    "agentInstinctSmall": "Connected · delivers the restaurant confirmation",
    "agentGrokSmall": "Connected · delivers flight price checks on a schedule",
    "agentTodaySmall": "Connected · organizes trip notes and source libraries",
    "agentDetailDefaultH": "Click an assistant to see what it handles.",
    "agentDetailDefaultP": "Each assistant works through its own connection, within the recipients and library scope you chose.",
    "descPrimaryTitle": "{primary} · Primary",
    "descPrimaryBody": "Collects results, saves them before acknowledging receipt, then reports to you. The role does not grant space administration access.",
    "descInstinctTitle": "Instinct · Connected",
    "descInstinctBody": "Delivers the restaurant confirmation to {primary}. It can exchange messages in this space, but cannot read unrelated messages.",
    "descGrokTitle": "Grok Bot · Connected",
    "descGrokBody": "Checks prices in its own runtime and sends options to {primary}. Shared materials stay in the space; no ticket is purchased.",
    "descTodayTitle": "Today · Connected",
    "descTodayBody": "Organizes shared trip notes for {primary}. Space members can read and update the materials, with versions preserved.",
    "libH": "One shared memory, maintained by you.",
    "libSub": "Shared libraries in your space",
    "libHelp": "Open the travel preferences to see the before-and-after record. Once authorized, a new assistant reads the same libraries; files and versions stay in Waypost across switches.",
    "pickFile": "Pick a sample library",
    "fileFlightSmall": "Grok Bot · flights & prices",
    "fileNotesSmall": "Today · trip notes",
    "fileQuestionsSmall": "Today · awaiting your call",
    "docSource": "Source: {actor} · shared within the space, with versions preserved",
    "docSourceInitial": "Source: Grok Bot · shared within the space, with versions preserved",
    "pickVersion": "View library versions",
    "verCurrent": "Version 2 · current",
    "verOld": "Version 1",
    "doc.flight.v2": "Outbound: Nov 6, departs 09:40, lands 14:35, S$540.\nReturn: Nov 13, S$598. Budget S$600.\nNothing ticketed yet; the return date needs your call.",
    "doc.flight.v1": "Outbound: Nov 6, departs 09:40, lands 14:35, S$560.\nReturn: Nov 13, S$625, over budget.\nThe previous check; nothing ticketed.",
    "doc.notes.v2": "Landing Fri 14:35, hotel first.\n19:00, Burnt Ends, table for two confirmed.\nOne guest avoids peanuts; the restaurant allows moving to Sat 20:00.",
    "doc.notes.v1": "Arriving Friday afternoon.\nDinner booking being confirmed; holding 19:00 for now.\nStill to add: dietary notes and rebooking terms.",
    "doc.questions.v2": "Please confirm the return on Nov 13.\nCurrent lowest S$598, inside the S$600 budget.\nOnce confirmed, let an assistant handle ticketing.",
    "doc.questions.v1": "Still to confirm: restaurant and return date.\nReturn at S$625 is over budget; keep watching prices.",
    "doc.prefs.v2": "This trip's per-person flight budget: S$600.\nOne guest avoids peanuts — note dietary needs before booking restaurants.\nReal ticketing and booking changes both wait for your confirmation.",
    "doc.prefs.v1": "This trip's per-person flight budget: S$600.\nDietary needs unconfirmed — ask again before booking restaurants.\nReal ticketing and booking changes both wait for your confirmation."
  },
  "zh": {
    "tabsLabel": "体验信箱、助手和资料",
    "owner": "旅行安排 · 示例空间",
    "agentsH": "谁把结果交给你？",
    "agentsSub": "角色与连接示例",
    "roleIntroHtml": "<p><strong>主助手</strong>是你主要对话的助手，负责汇总并向你汇报。<strong>接入助手</strong>交付各自的结果。</p><p>主助手可以是你现在使用的助手。来信计划接入，本页可以切换演示角色。</p>",
    "tryPrimary": "试试更换示例中的主助手",
    "optCustom": "你常用的助手",
    "optLaixin": "来信（计划接入）",
    "laixinName": "来信",
    "laixinPlan": "本页仅演示角色，来信产品接入仍在规划。",
    "primaryAvatar": "主",
    "filePrefsSmall": "你确认的偏好 · 预算与忌口",
    "prefsActor": "你确认",
    "primaryNoteDefault": "选择主助手会影响新连接的默认收件人。自动收取需要宿主调度或桥，已有连接保持不变。",
    "primaryNoteTpl": "示例中新连接默认发给「{primary}」。自动收取需要宿主调度或桥；已有连接和投递内容保持不变。",
    "primaryNoteTplLaixin": "示例中新连接默认发给「{primary}」。来信接入仍在规划中；自动收取需要宿主调度或桥。",
    "agentPrimarySmall": "主助手 · 汇总结果，向你汇报",
    "agentInstinctSmall": "接入助手 · 交付餐厅预约确认",
    "agentGrokSmall": "接入助手 · 定期交付机票查价",
    "agentTodaySmall": "接入助手 · 整理行程笔记与原始资料",
    "agentDetailDefaultH": "点击一个助手，看看它负责什么。",
    "agentDetailDefaultP": "每个助手有自己的连接，按你选定的收件人与资料范围工作。",
    "descPrimaryTitle": "{primary} · 主助手",
    "descPrimaryBody": "收取结果并可靠保存后确认回执，再向你汇报。这个角色不授予空间管理能力。",
    "descInstinctTitle": "Instinct · 接入助手",
    "descInstinctBody": "把餐厅确认交给 {primary}。它可以在空间内互发消息，但不能读取与自己无关的消息。",
    "descGrokTitle": "Grok Bot · 接入助手",
    "descGrokBody": "在自己的运行环境查价，将候选交给 {primary}。资料在空间内共享，没有执行购票。",
    "descTodayTitle": "Today · 接入助手",
    "descTodayBody": "整理共享行程笔记供 {primary} 继续使用。空间成员可读写资料，更新保留版本。",
    "libH": "同一份记忆，你来维护。",
    "libSub": "空间内共享资料示例",
    "libHelp": "点开旅行偏好，看看修改前后的记录。新助手获准后可以读同一份资料；换了助手，文件和版本仍留在 Waypost。",
    "pickFile": "选择示例资料",
    "fileFlightSmall": "Grok Bot · 航班与价格",
    "fileNotesSmall": "Today · 行程笔记",
    "fileQuestionsSmall": "Today · 等你决定的事",
    "docSource": "来源：{actor} · 空间内共享，保留版本",
    "docSourceInitial": "来源：Grok Bot · 空间内共享，保留版本",
    "pickVersion": "查看资料版本",
    "verCurrent": "版本 2 · 当前",
    "verOld": "版本 1",
    "doc.flight.v2": "去程：11 月 6 日，09:40 起飞，14:35 落地，S$540。\n回程：11 月 13 日，S$598。预算 S$600。\n还没有购票，回程日期需要你确认。",
    "doc.flight.v1": "去程：11 月 6 日，09:40 起飞，14:35 落地，S$560。\n回程：11 月 13 日，S$625，超过预算。\n这是上一次查价记录，尚未购票。",
    "doc.notes.v2": "周五 14:35 落地，先去酒店。\n19:00，Burnt Ends，两人位已确认。\n一位不吃花生；餐厅允许改到周六 20:00。",
    "doc.notes.v1": "周五下午抵达。\n晚餐预约正在确认，先留出 19:00。\n待补充：忌口与改期条件。",
    "doc.questions.v2": "请确认回程是否选 11 月 13 日。\n当前最低 S$598，在 S$600 预算内。\n确认以后，再让助手处理购票。",
    "doc.questions.v1": "待确认餐厅与回程日期。\n回程 S$625，超过预算；继续观察价格。",
    "doc.prefs.v2": "这次旅行每人的机票预算：S$600。\n一位不吃花生，预订餐厅前说明忌口。\n实际购票和修改预约，都先交给你确认。",
    "doc.prefs.v1": "这次旅行每人的机票预算：S$600。\n忌口尚未确认，订餐厅前需要再问。\n实际购票和修改预约，都先交给你确认。"
  }
};

  function lang() {
    const tag = document.documentElement.lang || 'en';
    return tag.toLowerCase().indexOf('zh') === 0 ? 'zh' : 'en';
  }
  function strings() { return D2[lang()] || D2.en; }
  function fill(template, params) {
    let out = template;
    for (const name in params) out = out.split('{' + name + '}').join(params[name]);
    return out;
  }

  let primary = 'usual', file = 'flight', revision = '2', agent = '';
  const sources = {
    preferences: { name: 'travel-preferences.md', actorKey: 'prefsActor', v2: 'docPrefsV2', v1: 'docPrefsV1' },
    flight: { name: 'flight-options.md', actor: 'Grok Bot', v2: 'docFlightV2', v1: 'docFlightV1' },
    notes: { name: 'trip-notes.md', actor: 'Today', v2: 'docNotesV2', v1: 'docNotesV1' },
    questions: { name: 'open-questions.md', actor: 'Today', v2: 'docQuestionsV2', v1: 'docQuestionsV1' }
  };
  function primaryName() {
    if (primary === 'laixin') return strings().laixinName;
    if (primary === 'usual') return strings().optCustom;
    return 'Muse';
  }

  function select(view) {
    for (const control of controls) {
      const active = control.dataset.preview === view;
      control.setAttribute('aria-selected', String(active));
      control.tabIndex = active ? 0 : -1;
      document.getElementById(control.getAttribute('aria-controls')).hidden = !active;
    }
  }
  for (const control of controls) {
    control.addEventListener('click', () => select(control.dataset.preview));
    control.addEventListener('keydown', event => {
      if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      const direction = ['ArrowRight', 'ArrowDown'].includes(event.key) ? 1 : -1;
      const index = event.key === 'Home' ? 0 : event.key === 'End' ? controls.length - 1 : (controls.indexOf(control) + direction + controls.length) % controls.length;
      select(controls[index].dataset.preview); controls[index].focus();
    });
  }
  function describeAgent(name) {
    agent = name;
    const copy = {
      primary: ['descPrimaryTitle', 'descPrimaryBody'],
      Instinct: ['descInstinctTitle', 'descInstinctBody'],
      'Grok Bot': ['descGrokTitle', 'descGrokBody'],
      Today: ['descTodayTitle', 'descTodayBody']
    }[name];
    if (!copy) return;
    const target = document.getElementById('demo-agent-detail');
    const title = document.createElement('h3'), body = document.createElement('p');
    title.textContent = fill(strings()[copy[0]], { primary: primaryName() });
    body.textContent = fill(strings()[copy[1]], { primary: primaryName() });
    if (primary === 'laixin') body.textContent += ' ' + strings().laixinPlan;
    target.replaceChildren(title, body);
    for (const button of document.querySelectorAll('[data-demo-agent]')) button.setAttribute('aria-pressed', String(button.dataset.demoAgent === name));
  }
  for (const button of document.querySelectorAll('[data-demo-agent]')) button.addEventListener('click', () => describeAgent(button.dataset.demoAgent));
  function showFile() {
    const source = sources[file];
    const actor = source.actorKey ? strings()[source.actorKey] : source.actor;
    document.getElementById('demo-document-name').textContent = source.name;
    document.getElementById('demo-document-source').textContent = fill(strings().docSource, { actor: actor });
    document.getElementById('demo-document-body').textContent = strings()[source[revision]];
    for (const button of document.querySelectorAll('[data-demo-file]')) button.setAttribute('aria-pressed', String(button.dataset.demoFile === file));
    for (const button of document.querySelectorAll('[data-demo-revision]')) button.setAttribute('aria-pressed', String(button.dataset.demoRevision === revision));
  }
  for (const button of document.querySelectorAll('[data-demo-file]')) button.addEventListener('click', () => { file = button.dataset.demoFile; showFile(); });
  for (const link of document.querySelectorAll('[data-show-file]')) link.addEventListener('click', () => {
    select('library'); file = link.dataset.showFile; revision = '2'; showFile();
  });
  for (const button of document.querySelectorAll('[data-demo-revision]')) button.addEventListener('click', () => { revision = button.dataset.demoRevision; showFile(); });
  function renderPrimaryNote() {
    const node = document.getElementById('demo-primary-note');
    if (!node) return;
    if (primary === 'laixin') {
      node.textContent = fill(strings().primaryNoteTplLaixin, { primary: primaryName() });
    } else if (primary === 'usual') {
      node.textContent = fill(strings().primaryNoteTpl, { primary: primaryName() });
    } else {
      node.textContent = strings().primaryNoteDefault;
    }
  }
  function renderPrimaryAvatar() {
    const node = document.getElementById('demo-primary-avatar');
    if (node) node.textContent = strings().primaryAvatar;
  }
  function renderRecipient() {
    if (typeof showScenario !== 'function') return;
    const selected = document.querySelector('[data-demo].selected')?.dataset.demo || 'message';
    showScenario(selected);
    for (const name of ['sender', 'recipient', 'body', 'status', 'receipt', 'caption']) {
      const node = document.getElementById(`demo-${name}`);
      node.textContent = node.textContent.split('Muse').join(primaryName());
    }
    document.getElementById('demo-announcement').textContent = document.getElementById('demo-subject').textContent + ' ' + document.getElementById('demo-caption').textContent;
  }
  document.getElementById('demo-primary').addEventListener('change', event => {
    primary = event.target.value;
    document.getElementById('demo-primary-name').textContent = primaryName();
    renderPrimaryAvatar();
    renderPrimaryNote();
    renderRecipient(); if (agent) describeAgent(agent); showFile();
  });
  for (const button of document.querySelectorAll('[data-demo]')) {
    button.addEventListener('click', renderRecipient);
    button.addEventListener('keydown', event => { if (['ArrowLeft', 'ArrowRight'].includes(event.key)) renderRecipient(); });
  }
  document.getElementById('demo-file').addEventListener('click', () => { select('library'); file = 'flight'; revision = '2'; showFile(); });

  document.addEventListener('waypost:lang', () => {
    renderPrimaryNote();
    renderPrimaryAvatar();
    document.getElementById('demo-primary-name').textContent = primaryName();
    const selectNode = document.getElementById('demo-primary');
    if (selectNode) {
      for (const option of selectNode.options) {
        if (option.value === 'usual') option.textContent = strings().optCustom;
        if (option.value === 'laixin') option.textContent = strings().optLaixin;
      }
    }
    if (agent) describeAgent(agent);
    showFile();
    renderRecipient();
  });
  renderRecipient();
})();
