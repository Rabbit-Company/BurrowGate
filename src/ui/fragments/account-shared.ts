export function usersModalMarkup(): string {
	return `<div id="modal-users" class="modal-overlay hidden" data-modal="users">
  <div class="modal modal-large">
    <div class="modal-header"><h2>Users</h2><button class="button secondary icon-button modal-close" type="button" data-modal-close aria-label="Close">&times;</button></div>
    <div class="modal-body">
      <article class="card user-create-card">
        <div class="pad section-heading"><div><h2>Add a user</h2><p class="muted">New accounts must enroll two-factor authentication on first login.</p></div></div>
        <div class="pad pad-topless"><form id="userForm" class="form-row"><label><span>Username</span><input class="input" name="username" autocomplete="off" required></label><label><span>Password</span><input class="input" type="password" name="password" autocomplete="new-password" required></label><label><span>Role</span><select class="select" name="role"><option value="member">Member</option><option value="administrator">Administrator</option></select></label><button class="button align-end" type="submit">Add user</button></form></div>
      </article>
      <article class="card users-list-card">
        <div class="pad section-heading"><div><h2>Users</h2><p class="muted">Administrators have full access. Members need explicit Viewer or Manager permission per site and stream.</p></div><button id="refreshUsers" class="button secondary">Refresh</button></div>
        <div class="table-wrap"><table class="table"><thead><tr><th>Username</th><th>Role</th><th>2FA</th><th>Enabled</th><th>Permissions</th><th></th></tr></thead><tbody id="users"><tr><td colspan="6" class="empty-cell">Open Users to load accounts.</td></tr></tbody></table></div>
      </article>
      <article id="userPermissionsCard" class="card user-permissions-card hidden">
        <div class="pad section-heading"><div><h2 id="userPermissionsTitle">Permissions</h2><p class="muted">Grant Viewer for read-only access, or Manager to allow configuration changes. Administrator accounts always have full access.</p></div><button id="closeUserPermissions" class="button secondary" type="button">Close</button></div>
        <div class="pad pad-topless">
          <h3>Sites</h3>
          <div id="userSitePermissions" class="permissions-grid"></div>
          <h3>Streams</h3>
          <div id="userStreamPermissions" class="permissions-grid"></div>
          <div class="row align-end"><button id="saveUserPermissions" class="button" type="button">Save permissions</button></div>
        </div>
      </article>
    </div>
  </div>
</div>`;
}

export function apiTokensCardMarkup(): string {
	return `<article id="apiTokensCard" class="card hidden">
        <div class="pad">
          <h2>API tokens</h2>
          <p class="muted">A full-access token can do anything your account can do through this dashboard - manage every site and stream you have permission for, exactly as if you were signed in. A read-only monitoring token (for TRMNL and similar tools) can only read aggregate metrics and it cannot change configuration or read secrets, captured requests, or sessions.</p>
          <form id="apiTokenForm" class="form-row">
            <label><span>Name</span><input class="input" name="name" maxlength="100" placeholder="TRMNL display" required></label>
            <label><span>Scope</span><select id="apiTokenScope" class="select" name="scope"><option value="full">Full access</option><option value="monitoring">Read-only monitoring</option></select></label>
            <label><span>Expires after</span><select class="select" name="expiresInDays"><option value="30">30 days</option><option value="90" selected>90 days</option><option value="365">1 year</option><option value="never">Never</option></select></label>
            <button class="button align-end" type="submit">Create token</button>
          </form>
          <div id="apiTokenCreated" class="notice hidden" role="status">
            <p>Copy this token now. It will not be shown again. Store it as securely as a password - a full-access token can do anything your account can do.</p>
            <label><span>New token</span><input id="apiTokenSecret" class="input" type="text" readonly autocomplete="off" spellcheck="false"></label>
            <button id="copyApiToken" class="button secondary compact" type="button">Copy token</button>
            <button id="dismissApiToken" class="button secondary compact" type="button">Done</button>
          </div>
          <ul id="apiTokenList" class="settings-list"></ul>
        </div>
      </article>`;
}
