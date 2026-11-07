// Airlock Interactive Documentation Scripts

document.addEventListener('DOMContentLoaded', () => {
  // 1. Copy Buttons
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');
      const textToCopy = targetId 
        ? document.getElementById(targetId)?.innerText 
        : btn.parentElement.querySelector('code')?.innerText;

      if (textToCopy) {
        navigator.clipboard.writeText(textToCopy).then(() => {
          const originalText = btn.innerHTML;
          btn.innerHTML = '✔ Copied!';
          btn.style.color = '#34d399';
          setTimeout(() => {
            btn.innerHTML = originalText;
            btn.style.color = '';
          }, 2000);
        });
      }
    });
  });

  // 2. Interactive Simulator
  const simInput = document.getElementById('sim-input');
  const simOutput = document.getElementById('sim-output');
  const presetBtns = document.querySelectorAll('.sim-preset-btn');

  const SIMULATION_RULES = [
    {
      pattern: /rm\s+.*-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)\s+.*\//,
      verdict: 'DENY',
      reason: 'Tier 0 Hard Deny: Destructive root filesystem deletion detected',
      latency: '0.04ms'
    },
    {
      pattern: /(?:cat|head|tail|grep)\s+.*~?\/?\.(?:ssh|aws|gemini|keychains|chat\.db|Cookies)/i,
      verdict: 'DENY',
      reason: 'Tier 0 Hard Deny: Direct access to protected credentials, browser sessions, or personal communication data',
      latency: '0.05ms'
    },
    {
      pattern: /\b(?:ngrok|cloudflared|ncat|netcat|socat)\b/,
      verdict: 'DENY',
      reason: 'Tier 0 Hard Deny: Unauthorized tunneling or port proxying utility detected',
      latency: '0.03ms'
    },
    {
      pattern: /<\|im_start\|>|ignore\s+all\s+previous\s+instructions|system\s+prompt\s+override/i,
      verdict: 'DENY',
      reason: 'Tier 0 Hard Deny: Adversarial prompt injection or system override sequence detected',
      latency: '0.02ms'
    },
    {
      pattern: /\b(?:printenv|env)\s+.*(?:KEY|TOKEN|SECRET|PASSWORD)/,
      test: (cmd) => {
        // Strip -u / --unset
        const sanitized = cmd.replace(/(?:\s|^)(?:-u\s*=?\s*|--unset\s*=?\s*)["']?[A-Za-z0-9_]+["']?/g, ' ');
        return /\b(?:printenv|env)\s+.*(?:KEY|TOKEN|SECRET|PASSWORD)/.test(sanitized);
      },
      verdict: 'DENY',
      reason: 'Tier 0 Hard Deny: Credential materialization from environment variable detected',
      latency: '0.04ms'
    },
    {
      pattern: /^(?:ls|pwd|whoami|git\s+(?:status|log|diff|branch)|date|uname|tree)/,
      verdict: 'ALLOW',
      reason: 'Tier 0 Fast-path: Verified safe read-only diagnostic command',
      latency: '0.04ms'
    },
    {
      pattern: /^ssh\s+[\w@.-]*cs\.umass\.edu\s+['"]?(?:sinfo|squeue|pestat|nvidia-smi)/,
      verdict: 'ALLOW',
      reason: 'Tier 0 Fast-path: Verified cluster node inspection on trusted host',
      latency: '0.06ms'
    },
    {
      pattern: /^env\s+(?:-u|--unset=)[\w_]+\s+(?:python3\s+-m\s+pytest|pytest|cargo\s+test)/,
      verdict: 'ALLOW',
      reason: 'Tier 0 Fast-path: Verified safe test runner with clean environment isolation',
      latency: '0.05ms'
    },
    {
      pattern: /^(?:cargo\s+test|npm\s+test|pytest|python3\s+-m\s+pytest)/,
      verdict: 'ALLOW',
      reason: 'Tier 0 Fast-path: Verified benign developer test suite execution',
      latency: '0.05ms'
    },
    {
      pattern: /^rm\s+-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)\s+(?:dist|build|target|node_modules|__pycache__)\b/,
      verdict: 'ALLOW',
      reason: 'Tier 0 Fast-path: Verified safe build artifact deletion',
      latency: '0.04ms'
    }
  ];

  function evaluateCommand(cmd) {
    const trimmed = cmd.trim();
    if (!trimmed) {
      simOutput.innerHTML = '<span style="color: var(--text-dim);">Enter a command or choose a preset above...</span>';
      return;
    }

    for (const rule of SIMULATION_RULES) {
      let matched = false;
      if (rule.test) {
        matched = rule.test(trimmed);
      } else if (rule.pattern) {
        matched = rule.pattern.test(trimmed);
      }

      if (matched) {
        if (rule.verdict === 'ALLOW') {
          simOutput.innerHTML = `
            <div class="verdict-allow">✔ allowed by Airlock classifier (${rule.latency})</div>
            <div style="color: #cbd5e1; margin-top: 0.5rem;">Verdict: ALLOW</div>
            <div style="color: #94a3b8; font-size: 0.85rem;">Reason: ${rule.reason}</div>
            <div class="verdict-meta">Evaluation Engine: Native compiled Rust (Tier 0 AST &amp; zero-allocation regex)</div>
          `;
        } else {
          simOutput.innerHTML = `
            <div class="verdict-deny">✖ denied by Airlock classifier (${rule.latency})</div>
            <div style="color: #cbd5e1; margin-top: 0.5rem;">Verdict: DENY (Immediate Execution Abort)</div>
            <div style="color: #fca5a5; font-size: 0.85rem;">Reason: ${rule.reason}</div>
            <div class="verdict-meta">Evaluation Engine: Native compiled Rust (Tier 0 Invariant Guardrail)</div>
          `;
        }
        return;
      }
    }

    // Default escalation simulation
    simOutput.innerHTML = `
      <div style="color: #fbbf24; font-weight: 700;">⚠ ESCALATED to Stage 1 Semantic Classifier</div>
      <div style="color: #cbd5e1; margin-top: 0.5rem;">Verdict: ESCALATE (Requires Model Review)</div>
      <div style="color: #94a3b8; font-size: 0.85rem;">Reason: Command involves workspace mutation; routed to warm gemini-3.8-flash-low daemon (~2.5s)</div>
      <div class="verdict-meta">Cryptographic nonce spotlighting active (&lt;untrusted_command_a8f93b21&gt;)</div>
    `;
  }

  if (simInput) {
    simInput.addEventListener('input', (e) => {
      evaluateCommand(e.target.value);
    });
  }

  presetBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const cmd = btn.getAttribute('data-cmd');
      if (simInput && cmd) {
        simInput.value = cmd;
        evaluateCommand(cmd);
      }
    });
  });

  // Run initial test
  if (simInput && simInput.value) {
    evaluateCommand(simInput.value);
  }
});
