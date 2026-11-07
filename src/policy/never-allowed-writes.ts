import { normalizeRemotePath, normalizeRemotePathForWindows } from './remote-path.js';

/**
 * Which of the README's never-allowed write families a path names.
 *
 * The README sentence covers two targets — writes to `/etc/cron` and
 * `/etc/systemd` (the `authorized_keys` family was removed locally: the
 * operator wants key writes gated only by `[policy].denylist`) — and this type
 * is how a refusal names which one fired, from either check site: the
 * classifier's shell-form rule and the engine's resource check.
 */
export type NeverAllowedWriteTarget = '/etc/cron' | '/etc/systemd';

/**
 * The `/etc` families are prefix matches with no boundary: `/etc/crontab` sits under
 * `/etc/cron` the same way `/etc/cron.d/x` does, which is how the redirect regex this
 * module replaces always read it. A sibling that merely starts like the directory
 * (`/etc/cronography`) fires too — over-refusal in the fail-closed direction this
 * engine takes everywhere else.
 */
const NEVER_DIRS = ['/etc/cron', '/etc/systemd'] as const;

/**
 * The refusal wording for a family, defined once because two check sites quote it:
 * the classifier's ForbiddenRule label and the engine's built-in deny reason.
 */
export function neverAllowedWriteLabel(target: NeverAllowedWriteTarget): string {
  switch (target) {
    case '/etc/cron': return 'writing to /etc/cron';
    case '/etc/systemd': return 'writing to /etc/systemd';
  }
}

function familyOf(path: string): NeverAllowedWriteTarget | null {
  for (const dir of NEVER_DIRS) {
    if (path.startsWith(dir)) return dir;
  }
  return null;
}

/**
 * Whether `path` names one of the never-allowed write targets, in any spelling the
 * path readings resolve.
 *
 * The same three readings `[policy].denylist` sees (#230): the path as given; a
 * lexically normalized reading (`//`, `/./`, `..`, trailing separators, `\` as a
 * separator); and the Windows reading of it, case-insensitively. On a POSIX
 * target some of those are different files; refusing them is the safe direction, the
 * same trade the operator denylist already makes.
 *
 * What this does not do is resolve anything on the target: a relative path stays
 * relative, symlinks are not followed, and an 8.3 short name is not expanded (#230's
 * documented residuals, inherited here).
 */
export function findNeverAllowedWriteTarget(path: string): NeverAllowedWriteTarget | null {
  return familyOf(path)
    ?? familyOf(normalizeRemotePath(path))
    ?? familyOf(normalizeRemotePathForWindows(path).toLowerCase());
}
