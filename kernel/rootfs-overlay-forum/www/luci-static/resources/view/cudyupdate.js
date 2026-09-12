'use strict';
'require view';
'require fs';
'require ui';
'require poll';

/* Cudy WR3600 port: System -> Firmware update (GitHub). Talks to
 * /usr/bin/cudy-update (check / install / status / slots / to-stock). */

function run(args) {
	return fs.exec('/usr/bin/cudy-update', args).then(function(res) {
		var out = (res.stdout || '').trim();
		try { return JSON.parse(out); } catch (e) { return { ok: false, error: out || res.stderr || ('exit ' + res.code) }; }
	});
}

return view.extend({
	load: function() {
		return Promise.all([ run(['check']), run(['slots']) ]);
	},

	render: function(data) {
		var check = data[0] || {}, slots = data[1] || {};
		var status = E('div', { 'class': 'cbi-value' });
		var body = E('div');

		var info = E('table', { 'class': 'table' }, [
			E('tr', { 'class': 'tr' }, [ E('td', { 'class': 'td left', 'width': '33%' }, _('Installed version')), E('td', { 'class': 'td left' }, check.current || '?') ]),
			E('tr', { 'class': 'tr' }, [ E('td', { 'class': 'td left' }, _('Latest release on GitHub')),
				E('td', { 'class': 'td left' }, check.ok ? [ check.latest, ' ', E('a', { 'href': check.notes_url, 'target': '_blank' }, _('(release notes)')) ] : (check.error || _('unknown'))) ]),
			E('tr', { 'class': 'tr' }, [ E('td', { 'class': 'td left' }, _('Running slot')), E('td', { 'class': 'td left' }, String(slots.running || '?')) ]),
			E('tr', { 'class': 'tr' }, [ E('td', { 'class': 'td left' }, _('Other slot holds')), E('td', { 'class': 'td left' }, slots.other_content || '?') ])
		]);

		var btnInstall = E('button', { 'class': 'btn cbi-button cbi-button-apply', 'disabled': !check.ok,
			'click': ui.createHandlerFn(this, function() {
				var force = !check.update_available;
				return ui.showModal(_('Install firmware'), [
					E('p', force ? _('You already run the latest release. Reinstall it into the other slot anyway?')
					             : _('Download and install %s? Settings are kept. The other slot is overwritten and the router reboots (2-4 minutes).').format(check.latest)),
					E('div', { 'class': 'right' }, [
						E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ',
						E('button', { 'class': 'btn cbi-button-action important', 'click': ui.createHandlerFn(this, function() {
							ui.hideModal();
							return run(force ? ['install', '--force'] : ['install']).then(function() { startPoll(); });
						}) }, _('Install'))
					])
				]);
			}) }, check.update_available ? _('Install %s').format(check.latest) : _('Reinstall latest'));

		var btnStock = E('button', { 'class': 'btn cbi-button cbi-button-negative',
			'disabled': slots.other_content !== 'factory',
			'click': ui.createHandlerFn(this, function() {
				return ui.showModal(_('Return to the factory firmware'), [
					E('p', _('The router will boot the factory firmware from slot %d and reboot now. This firmware stays in its slot; the factory web interface will be at 192.168.10.1.').format(slots.other)),
					E('div', { 'class': 'right' }, [
						E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ',
						E('button', { 'class': 'btn cbi-button-negative important', 'click': ui.createHandlerFn(this, function() {
							ui.hideModal();
							return run(['to-stock']).then(function() {
								ui.showModal(_('Rebooting to the factory firmware'), [ E('p', { 'class': 'spinning' }, _('Wait about two minutes.')) ]);
								ui.awaitReconnect('192.168.10.1');
							});
						}) }, _('Boot factory firmware'))
					])
				]);
			}) }, _('Return to factory firmware'));

		function startPoll() {
			ui.showModal(_('Updating'), [ E('p', { 'class': 'spinning' }, _('Starting…')) ]);
			poll.add(function() {
				return run(['status']).then(function(st) {
					var m = document.querySelector('.modal p');
					if (m) m.textContent = (st.message || st.state) + (st.progress ? ' (' + st.progress + '%)' : '');
					if (st.state == 'error') { poll.stop(); ui.hideModal(); ui.addNotification(null, E('p', _('Update failed: %s').format(st.message)), 'error'); }
					if (st.state == 'done' && st.message.indexOf('already') == 0) { poll.stop(); ui.hideModal(); ui.addNotification(null, E('p', st.message)); }
					if (st.state == 'flashing') { poll.stop(); ui.awaitReconnect(window.location.host, '192.168.10.1'); }
				});
			}, 2);
		}

		body.appendChild(E('h2', _('Firmware update')));
		body.appendChild(E('p', _('Releases are fetched from GitHub (%s). An update writes the other slot, keeps your settings and reboots; the slot you run now stays as a fallback.').format('github.com/nomorecoolnicknames/cudy-wr3600-openwrt')));
		body.appendChild(info);
		body.appendChild(E('div', { 'class': 'cbi-page-actions' }, [ btnInstall, ' ', btnStock ]));
		if (slots.other_content && slots.other_content !== 'factory')
			body.appendChild(E('p', { 'class': 'alert-message warning' }, _('The factory firmware is no longer in the other slot (it holds "%s"), so "Return to factory firmware" is disabled. Cudy\'s TFTP recovery with the signed factory image is the only way back.').format(slots.other_content)));
		return body;
	},

	handleSaveApply: null, handleSave: null, handleReset: null
});
