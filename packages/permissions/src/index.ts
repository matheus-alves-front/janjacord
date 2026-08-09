import type { Channel, PermissionFlag, Role } from "@janjacord/schemas";

/**
 * Avaliação de permissões (spec roles-and-channel-permissions):
 * precedência: deny explícito do canal > allow explícito do canal > permissão da role > server default.
 * Owner (level >= 100) sempre vence, exceto contra outro Owner (decisão hierárquica).
 */
export interface MemberContext {
  identityId: string;
  roleId: string;
  isOwner: boolean;
}

export function evaluatePermission(
  member: MemberContext,
  role: Role,
  channel: Channel | null,
  permission: PermissionFlag,
): boolean {
  // Owner override (ADR/permissions spec): level 100 = dono.
  if (member.isOwner || role.level >= 100) return true;

  const override = channel?.overrides.find((o) => o.roleId === role.id);
  if (override) {
    if (override.deny.includes(permission)) return false;
    if (override.allow.includes(permission)) return true;
  }

  return role.permissions.includes(permission);
}

/** Ações administrativas exigem hierarquia: quem age precisa de level maior que o alvo. */
export function canModify(
  actor: MemberContext & { role: Role },
  targetRole: Role,
  permission: PermissionFlag,
): boolean {
  if (!evaluatePermission(actor, actor.role, null, permission)) return false;
  if (actor.isOwner || actor.role.level >= 100) return targetRole.level < 100; // owner não se auto-rebaixa
  return actor.role.level > targetRole.level;
}
