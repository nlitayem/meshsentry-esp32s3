/*
 * Attack emulation for the MeshSentry testbed (role "Attacker" only).
 * For controlled experiments on equipment you own; do not deploy.
 */
#pragma once

#include "mesh.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Behaviour hooks to install with mesh_start(). */
void attack_hooks(mesh_hooks_t *hooks, mesh_config_t *cfg);

/* Start attack tasks; call after mesh_start(). */
void attack_start(void);

#ifdef __cplusplus
}
#endif
