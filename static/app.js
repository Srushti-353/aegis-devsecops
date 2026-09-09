document.addEventListener('DOMContentLoaded', function () {
  const statusNodes = document.querySelectorAll('.status-card strong');
  statusNodes.forEach((node) => {
    const text = node.textContent.trim();
    if (text === 'VERIFIED') {
      node.style.color = '#34d399';
    }
  });

  const form = document.getElementById('investigation-form');
  const status = document.getElementById('investigation-status');
  const results = document.getElementById('investigation-results');
  const errorBox = document.getElementById('investigation-error');
  const button = document.getElementById('run-investigation');
  if (!form) return;

  const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
  }[character]));

  const displayValue = (value, fallback = 'Not available') => {
    if (value === null || value === undefined || value === '') return fallback;
    if (Array.isArray(value)) {
      return value.length ? value.map((item) => displayValue(item, fallback)).join(' / ') : fallback;
    }
    if (typeof value === 'object') return Object.entries(value).map(([key, item]) => `${key}: ${displayValue(item)}`).join('; ');
    return String(value);
  };

  const escapedValue = (value, fallback) => escapeHtml(displayValue(value, fallback));

  const formatApiError = (data) => {
    if (Array.isArray(data && data.detail)) {
      return data.detail.map((item) => {
        const location = Array.isArray(item.loc) ? item.loc.join('.') : 'request';
        return `${location}: ${item.msg || 'Invalid value'}`;
      }).join('; ');
    }
    if (data && typeof data.detail === 'string') return data.detail;
    return 'Request failed. Check API contract.';
  };

  const renderRemediationPlan = (plan) => {
    const commands = Array.isArray(plan.commands) ? plan.commands : (plan.commands ? [plan.commands] : []);
    const verification = Array.isArray(plan.verification) ? plan.verification : (plan.verification ? [plan.verification] : []);
    return `
      <div class="live-remediation-label">AEGIS INVESTIGATION</div>
      <h4>Finding</h4><p>${escapedValue(plan.finding_id)} · ${escapedValue(plan.cve || plan.finding_id)}</p>
      <h4>Evidence</h4>
      <p>Scanner: ${escapedValue(plan.source)} · Package: ${escapedValue(plan.package)}</p>
      <p>Installed version: ${escapedValue(plan.installed_version)} · Patched versions: ${escapedValue(plan.recommended_version)}</p>
      <h4>REMEDIATION PLAN</h4>
      <p><strong>Proposed remediation:</strong> ${escapedValue(plan.action)}</p>
      ${plan.reason ? `<p><strong>Why this fixes the issue:</strong> ${escapedValue(plan.reason)}</p>` : ''}
      ${commands.length ? `<p><strong>Suggested developer command:</strong><br>${commands.map((command) => escapedValue(command)).join('<br>')}</p>` : '<p><strong>Suggested developer command:</strong> Not available</p>'}
      <p class="not-executed">STATUS: PROPOSED - NOT EXECUTED</p>
      <h4>VERIFICATION PLAN</h4>
      ${verification.length ? `<ol>${verification.map((step) => `<li>${escapedValue(step)}</li>`).join('')}</ol>` : '<p>Verification required: re-run AEGIS after a patched revision is available.</p>'}
      <p><strong>Verification required.</strong> ${escapedValue(plan.execution_status, 'Re-run AEGIS after a patched revision is available.')}</p>
      <button type="button" class="verify-after-fix">VERIFY AFTER FIX</button>`;
  };

  const renderRootCause = (rootCause) => {
    if (!rootCause || rootCause.status === 'not_attributable') {
      return `<h4>ROOT CAUSE</h4><p>Not attributable: ${escapedValue(rootCause && rootCause.attribution_method, 'Insufficient Git history evidence.')}</p>`;
    }
    return `<h4>ROOT CAUSE</h4><p>Commit: ${escapedValue(rootCause.introducing_commit)}</p><p>Message: ${escapedValue(rootCause.commit_message)}</p><p>Affected file: ${escapedValue(rootCause.affected_file)}</p><p>Method: ${escapedValue(rootCause.attribution_method)} · Confidence: ${escapedValue(rootCause.confidence)}</p>`;
  };

  const setStage = (index) => {
    status.querySelectorAll('.loading-stage').forEach((node, nodeIndex) => {
      node.classList.toggle('active', nodeIndex === index);
      node.classList.toggle('complete', nodeIndex < index);
    });
  };

  const renderResults = (investigation) => {
    const profile = investigation.profile;
    const summary = investigation.summary;
    const renderFinding = (finding, index) => `
      <article class="finding-card" data-finding-index="${index}">
        <div class="finding-card-header"><span class="severity severity-${escapeHtml(finding.severity.toLowerCase())}">${escapeHtml(finding.severity)}</span><span>${escapeHtml(finding.category)}</span></div>
        <h4>${escapeHtml(finding.title || finding.id)}</h4>
        <p>CVE/rule ID: ${escapeHtml(finding.cve || finding.id)}</p>
        ${finding.package ? `<p>Package: ${escapeHtml(finding.package)}</p>` : ''}
        ${finding.installed_version ? `<p>Installed version: ${escapeHtml(finding.installed_version)}</p>` : ''}
        ${finding.fixed_version ? `<p>Fixed version: ${escapeHtml(finding.fixed_version)}</p>` : ''}
        <p>Scanner: ${escapeHtml(finding.source)}</p>
        <details><summary>Evidence details</summary><p>${escapeHtml(finding.description || 'No additional description')}</p><p>${escapeHtml(finding.file || 'Repository-wide')}</p></details>
        <button type="button" class="investigate-finding">INVESTIGATE</button>
        <div class="remediation-panel" hidden></div>
      </article>`;
    const scannerRows = investigation.scanner_results.map((scanner) =>
      `<div><strong>${escapeHtml(scanner.scanner.toUpperCase())}</strong><span>${escapeHtml(scanner.status)}${scanner.error ? `<small>${escapeHtml(scanner.error)}</small>` : ''}</span></div>`
    ).join('');
    const findingIndex = (finding) => investigation.findings.findIndex((candidate) => (
      candidate.source === finding.source &&
      candidate.id === finding.id &&
      candidate.package === finding.package &&
      candidate.installed_version === finding.installed_version &&
      candidate.file === finding.file
    ));
    const topFindingCards = investigation.top_findings.map((finding) => renderFinding(finding, findingIndex(finding))).join('');
    const allFindingCards = investigation.findings.map((finding, index) => renderFinding(finding, index)).join('');
    results.innerHTML = `
      <div class="scan-complete">SCAN COMPLETE</div>
      <div class="investigation-result-header"><h3>Repository</h3><span>${escapeHtml(investigation.repository_url)}</span></div>
      <div class="investigation-result-header"><h3>Technology profile</h3><span>${escapeHtml(profile.file_count)} files</span></div>
      <p class="profile-values">${escapeHtml(profile.languages.join(' · ') || 'Unknown language')} ${profile.docker ? ' · Docker' : ''} ${profile.terraform ? ' · Terraform' : ''} ${profile.kubernetes ? ' · Kubernetes' : ''}</p>
      <h3>Scanners used</h3><div class="scanner-status">${scannerRows}</div>
      <div class="security-summary counts"><div><strong>${investigation.raw_finding_count}</strong><span>RAW FINDINGS</span></div><div><strong>${investigation.unique_finding_count}</strong><span>UNIQUE FINDINGS</span></div>${['critical', 'high', 'medium', 'low'].map((key) => `<div><strong>${summary[key]}</strong><span>${key.toUpperCase()}</span></div>`).join('')}</div>
      <h3>TOP SECURITY FINDINGS</h3>${topFindingCards || '<div class="empty-findings">NO SUPPORTED SECURITY FINDINGS DETECTED</div>'}
      ${investigation.findings.length > investigation.top_findings.length ? `<button type="button" class="view-all-findings" data-expanded="false">VIEW ALL FINDINGS</button><div class="all-findings" hidden>${allFindingCards}</div>` : ''}`;
    results.hidden = false;
    const viewAll = results.querySelector('.view-all-findings');
    if (viewAll) viewAll.addEventListener('click', () => {
      const all = results.querySelector('.all-findings');
      all.hidden = !all.hidden;
      viewAll.textContent = all.hidden ? 'VIEW ALL FINDINGS' : 'HIDE ADDITIONAL FINDINGS';
    });
    results.querySelectorAll('.investigate-finding').forEach((investigateButton) => {
      investigateButton.addEventListener('click', async () => {
        const card = investigateButton.closest('.finding-card');
        const panel = card.querySelector('.remediation-panel');
        const finding = investigation.findings[Number(card.dataset.findingIndex)];
        investigateButton.disabled = true;
        panel.hidden = false;
        panel.innerHTML = '<p>Preparing deterministic remediation plan...</p>';
        try {
          const response = await fetch('/api/remediation-plan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ finding, repository_url: investigation.repository_url })
          });
          const payload = await response.json().catch(() => ({}));
          if (!response.ok) throw new Error(formatApiError(payload));
          const plan = payload.plan;
          if (!plan || typeof plan !== 'object') throw new Error('Remediation plan response was not structured');
          let rootCauseMarkup = '<h4>ROOT CAUSE</h4><p>Evidence collection unavailable.</p>';
          try {
            const rootCauseResponse = await fetch('/api/root-cause', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ finding, repository_url: investigation.repository_url })
            });
            const rootCausePayload = await rootCauseResponse.json().catch(() => ({}));
            if (rootCauseResponse.ok) rootCauseMarkup = renderRootCause(rootCausePayload.root_cause);
            else rootCauseMarkup = `<h4>ROOT CAUSE</h4><p>${escapeHtml(formatApiError(rootCausePayload))}</p>`;
          } catch (rootCauseError) {
            console.error('Root-cause attribution failed', rootCauseError);
          }
          panel.innerHTML = `<div class="deterministic-evidence"><strong>DETERMINISTIC / SCANNER EVIDENCE</strong>${rootCauseMarkup}</div>${renderRemediationPlan(plan)}`;
          panel.querySelector('.verify-after-fix').addEventListener('click', () => {
            const patchedUrl = window.prompt('Public GitHub URL for the patched repository revision:');
            if (!patchedUrl) return;
            const verificationNote = panel.querySelector('.verification-note-live') || document.createElement('p');
            verificationNote.className = 'verification-note-live';
            verificationNote.textContent = 'Verifying patched repository...';
            panel.appendChild(verificationNote);
            fetch('/api/verify-repository', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ finding, repository_url: investigation.repository_url, patched_repository_url: patchedUrl })
            }).then(async (verificationResponse) => {
              const verification = await verificationResponse.json().catch(() => ({}));
              verificationNote.textContent = verificationResponse.ok
                ? `${verification.status}: ${verification.reason}`
                : formatApiError(verification);
            }).catch(() => {
              verificationNote.textContent = 'Verification failed. The patched repository could not be scanned.';
            });
          });
        } catch (error) {
          console.error('Remediation plan failed', error);
          panel.innerHTML = `<div class="alert-box">${escapeHtml(error instanceof Error ? error.message : 'Unable to create remediation plan')}</div>`;
        } finally {
          investigateButton.disabled = false;
        }
      });
    });
  };

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    status.hidden = false;
    results.hidden = true;
    errorBox.hidden = true;
    button.disabled = true;
    setStage(0);
    try {
      const repositoryUrl = form.querySelector('[name="repository_url"]').value.trim();
      const response = await fetch('/api/investigate-repository', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repository_url: repositoryUrl })
      });
      setStage(2);
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.detail || 'Investigation failed');
      setStage(4);
      renderResults(payload);
    } catch (error) {
      console.error('Repository investigation failed', error);
      errorBox.textContent = error instanceof Error ? error.message : 'Investigation failed';
      errorBox.hidden = false;
    } finally {
      button.disabled = false;
    }
  });
});
