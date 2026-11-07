import { describe, expect, it } from 'vitest';
import {
  findNeverAllowedWriteTarget,
  neverAllowedWriteLabel,
} from '../../../src/policy/never-allowed-writes.js';
import { findForbiddenMatch } from '../../../src/policy/classifier.js';

const CRON = 'writing to /etc/cron';
const SYSTEMD = 'writing to /etc/systemd';
const DD_DEVICE = 'dd writing to a block device (of=/dev/…)';

describe('the never-allowed write forms (findForbiddenMatch)', () => {
  describe('refuses', () => {
    it.each([
      // Redirects (cron/systemd spellings; authorized_keys redirects moved to the
      // allowed table below — that family was removed locally).
      ['echo x 2> /etc/cron.d/y', CRON],
      ['echo x 2>> /etc/cron.d/y', CRON],
      ['echo x &> /etc/cron.d/y', CRON],
      ['echo x > /etc/cron.d/y', CRON],
      ['echo x > //etc/cron.d/y', CRON],
      ['echo x > /etc/systemd/system/x.service', SYSTEMD],
      // Write verbs, destination operand.
      ['sudo tee -a /etc/cron.d/x', CRON],
      ['cp -t /etc/cron.d x', CRON],
      ['cp --target-directory=/etc/cron.d x', CRON],
      ['install -d /etc/cron.d/x', CRON],
      ['mv k /etc/systemd/system/x.service', SYSTEMD],
      // Wrappers and carriers.
      ['echo $(tee -a /etc/cron.d/x)', CRON],
      // Redirect operator spellings the review round added.
      ['echo x >|/etc/cron.d/y', CRON],
      ['echo x 2>| /etc/systemd/system/x.service', SYSTEMD],
      ['echo x >&/etc/cron.d/y', CRON],
      ['echo x &>>/etc/cron.d/y', CRON],
      // A quoted segment must not cut the tail the shell appends to it.
      ['echo x >/etc/cron.d/"y"', CRON],
      // The -t destination in every spelling GNU accepts.
      ['cp --target-directory /etc/cron.d x', CRON],
      ['cp -t/etc/cron.d x', CRON],
      ['install --target-directory /etc/cron.d k', CRON],
      // A wrapper's own value-taking flag must not hide the verb it wraps.
      ['xargs -d "\\n" cp k /etc/cron.d/x', CRON],
      // GNU permutes options to the end; the value must not displace the destination.
      ['cp k /etc/cron.d/y -Z context', CRON],
      ['install --directory /etc/cron.d/x', CRON],
      // The older dd block-device rule through a wrapper (review round: it read the
      // head with the privilege-prefix-only machine and missed `env dd`).
      ['env dd of=/dev/sda', DD_DEVICE],
    ])('%s', (command, label) => {
      expect(findForbiddenMatch(command)).toBe(label);
    });
  });

  describe('does not refuse', () => {
    it.each([
      // Reads stay allowed.
      'cat ~/.ssh/authorized_keys',
      'grep -c ssh /etc/cron.d/x',
      'tail /etc/systemd/system/x.service',
      // Mentions are not writes (the maintainer's speculativeOperands ruling).
      "git commit -m 'tee -a /etc/cron.d/x'",
      'git commit -m "echo x > /etc/cron"',
      'echo "> /etc/cron.d/y"',
      'echo "cp k /root/.ssh/authorized_keys"',
      // authorized_keys writes: the family was removed locally — gate them with
      // [policy].denylist instead of the built-in list.
      'echo k > ~/.ssh/authorized_keys',
      'echo k > /root/.ssh/authorized_keys',
      'echo k > ~root/.ssh/authorized_keys',
      'echo k >>/root/.ssh/authorized_keys',
      'echo k >"/root/.ssh/authorized_keys"',
      'echo k > "/root/.ssh/authorized_keys"',
      'echo k > C:\\Users\\a\\.ssh\\authorized_keys',
      'tee -a ~/.ssh/authorized_keys',
      'cp k ~/.ssh/authorized_keys',
      'cp authorized_keys ~/.ssh/',
      'install -m 600 k /root/.ssh/authorized_keys',
      'dd of=/root/.ssh/authorized_keys',
      'sudo cp k /root/.ssh/authorized_keys',
      'env cp k /root/.ssh/authorized_keys',
      'sh -c "cp k /root/.ssh/authorized_keys"',
      'echo k >/root/.ssh/authorized_keys;id',
      'echo k >| ~/.ssh/authorized_keys',
      'echo k > "rel"/.ssh/authorized_keys',
      'echo k > ""~/.ssh/authorized_keys',
      'xargs -I {} cp {} /root/.ssh/authorized_keys',
      'install k /root/.ssh/authorized_keys -m 600',
      'install k /root/.ssh/authorized_keys -m600',
      'cp k C:\\Users\\a\\.ssh\\authorized_keys',
      // Uncovered writes and non-targets.
      'echo x > /tmp/y',
      'cp k /tmp/authorized_keys',
      'sed -i 1d ~/.ssh/authorized_keys',
      'rsync k /root/.ssh/authorized_keys',   // the spec's named residual verb
      'tee --help',
      'cp k',
      'cp -t',                                 // a -t with no value is cp's own usage error
      "cp -t '' x /etc/cron.d",                // an empty -t value names no destination
      'echo x >',
    ])('%s', (command) => {
      expect(findForbiddenMatch(command)).toBeNull();
    });
  });
});

describe('findNeverAllowedWriteTarget', () => {
  describe('the /etc/cron family', () => {
    it.each([
      '/etc/cron.d/x',
      '/etc/crontab',                 // covered by the prefix reading, as the old regex read it
      '/etc/cron.daily/backup',
      '/etc/cron',                    // the directory itself
      '//etc/cron.d/x',               // normalized reading
      '/etc/./cron.d/x',
      '/etc/cron.d/../cron.d/x',
      '/etc/cron.d/x/',               // trailing separator
      '/ETC/CRON.D/X',                // Windows reading, case-insensitive
      '\\etc\\cron.d\\x',
    ])('%s names a covered path', (path) => {
      expect(findNeverAllowedWriteTarget(path)).toBe('/etc/cron');
    });

    it.each([
      'etc/cron.d/x',                 // relative: no absolute /etc
      '/var/etc/cron.d/x',
      '/etc/passwd',
      '/home/u/cron.d/x',
    ])('%s does not', (path) => {
      expect(findNeverAllowedWriteTarget(path)).toBeNull();
    });
  });

  describe('the /etc/systemd family', () => {
    it.each([
      '/etc/systemd/system/x.service',
      '//etc/systemd/system/x.service',
      '/ETC/SYSTEMD/system/x.service',
      '\\etc\\systemd\\system\\x.service',
    ])('%s names a covered path', (path) => {
      expect(findNeverAllowedWriteTarget(path)).toBe('/etc/systemd');
    });

    it.each(['/usr/lib/systemd/system/x.service', '/etc/system'])('%s does not', (path) => {
      expect(findNeverAllowedWriteTarget(path)).toBeNull();
    });
  });

  describe("the removed authorized_keys family (gated only by [policy].denylist now)", () => {
    it.each([
      '~/.ssh/authorized_keys',
      '~root/.ssh/authorized_keys',
      '/root/.ssh/authorized_keys',
      '/home/u/.ssh/authorized_keys',
      '.ssh/authorized_keys',         // relative
      '~/.ssh//authorized_keys',      // normalized reading
      '~/x/../.ssh/authorized_keys',
      'C:\\Users\\a\\.ssh\\authorized_keys',
      'C:/Users/a/.ssh/AUTHORIZED_KEYS.',   // Windows reading: case + trailing dot
      '\\\\server\\share\\.ssh\\authorized_keys::$DATA',
      '\\\\?\\C:\\x\\.ssh\\authorized_keys',
    ])('%s is no longer a covered path', (path) => {
      expect(findNeverAllowedWriteTarget(path)).toBeNull();
    });

    it.each([
      '~/.ssh/authorized_keys2',
      '~/.ssh/id_ed25519',
      '/home/u/docs/authorized_keys', // not inside .ssh
      'authorized_keys',              // a bare filename is not the path
      '',
      '.',
      '/tmp/x',
    ])('%s does not', (path) => {
      expect(findNeverAllowedWriteTarget(path)).toBeNull();
    });
  });

  it('labels name the family for refusal wording', () => {
    expect(neverAllowedWriteLabel('/etc/cron')).toBe('writing to /etc/cron');
    expect(neverAllowedWriteLabel('/etc/systemd')).toBe('writing to /etc/systemd');
  });
});
