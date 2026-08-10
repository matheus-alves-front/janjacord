# ADR-010 — shadcn Design Language

- **Status:** accepted (2026-08-09)
- **Contexto:** UI precisa ser moderna, densa, com ótimos estados — sem copiar Discord, sem
  estética hacker.
- **Decisão:** shadcn/ui de verdade no desktop (código dos componentes no projeto, controle
  integral); tokens/spacing/radius/typography/states/linguagem de interação compartilhados no
  `design-tokens` package; equivalentes nativos no mobile. Visual ≈ desktop, arquitetura ≠.
  Dark mode de alta qualidade; sem placeholder; sem template feel.
- **Consequências:** mais código de UI para manter (aceito — controle total);
  design-ui-ux-designer como gate antes de frontend; UI-UX-EVIDENCE por fluxo.
- **Spec:** `desktop-ui-ux-contract.md`, `mobile-ui-ux-contract.md`
- **Refs:** ui.shadcn.com/docs
