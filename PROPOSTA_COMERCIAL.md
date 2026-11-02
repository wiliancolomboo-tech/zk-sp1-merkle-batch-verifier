# Proposta Comercial: SP1 ZK-Coprocessor: High-Throughput Merkle Batch Verifier

- **Plataforma:** DoraHacks
- **Link:** https://dorahacks.io/bounty/sp1-merkle-batch-verifier
- **Orçamento Cliente:** 4,500 USDC
- **Investimento Sugerido:** $ 4,500.00
- **Prazo de Entrega:** 14 dias úteis

---

### ⚡ 1. PROPOSTA DIRETA & EXPRESS (Recomendada p/ Fechamento Rápido)

O desafio é validar 1.024 leaves via SNARK recursivo mantendo o settlement EVM abaixo de 50k gas.
Entrego circuito/prover, verificador Solidity e benchmarks reproduzíveis em 14 dias por $4.500 USDC.
Wilian, podemos alinhar hoje o hash, a profundidade da Merkle tree e o ambiente EVM alvo?

---

### 🌟 2. PROPOSTA TÉCNICA ESTRUTURADA (Diagnóstico + Solução)

Entendimento do desafio: verificar 1.024 withdrawals em lote com alta vazão, prova recursiva e settlement EVM estritamente abaixo de 50k gas.
Abordagem técnica: programa SP1 em Rust para agregação determinística, compressão recursiva da prova e verificador Solidity otimizado, com benchmarks em Foundry.
Entregáveis & prazo: circuito, scripts de witness/proof, contrato verificador, testes E2E, documentação e benchmark de gás em 14 dias. Investimento: $4.500 USDC.
Próximo passo: Wilian Colombo, confirme o formato das leaves, a profundidade da árvore, o proof system e a rede EVM alvo para iniciarmos.

---

### 💎 3. OPÇÃO PREMIUM / ENTERPRISE (Garantia & Suporte Estendido)

Proponho um ZK-coprocessor auditável e escalável, preparado para batches maiores sem redesenhar o fluxo: circuito recursivo parametrizado, pipeline determinístico de provas e verificador Solidity otimizado para settlement sub-50k gas.
Incluo testes unitários, fuzzing, validação de casos de borda, benchmarks reproduzíveis, documentação operacional e critérios objetivos de aceite: provas válidas, equivalência funcional e limite de gás no ambiente acordado.
Prazo: 14 dias | Investimento: $4.500 USDC.
Após a entrega, ofereço suporte técnico para correções relacionadas ao escopo, tuning de performance e integração em testnet.
