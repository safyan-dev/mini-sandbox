# MiniSandbox

A small, dependency-free Python controller that runs **untrusted Python programs**
inside a restricted Linux container on macOS. The goal is education: see how
sandboxing actually works, not to build a product.

## Features (built one stage at a time)

| # | Feature               | Status |
|---|-----------------------|--------|
| 1 | Sandbox creation      | done (Stage 3) |
| 2 | Code execution        | done (Stage 3) |
| 3 | Filesystem isolation  | done (Stage 4) |
| 4 | Network isolation     | done (Stage 6) |
| 5 | Process isolation     | done (Stage 5) |
| 6 | Resource limits       | done (Stage 6) |
| 7 | Execution timeout     | done (Stage 6) |
| 8 | Sandbox destruction   | done (Stage 3) |
