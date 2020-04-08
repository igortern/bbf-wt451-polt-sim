/*
 *  <:copyright-BRCM:2016-2020:Apache:standard
 *  
 *   Copyright (c) 2016-2020 Broadcom. All Rights Reserved
 *  
 *   The term “Broadcom” refers to Broadcom Inc. and/or its subsidiaries
 *  
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *  
 *       http://www.apache.org/licenses/LICENSE-2.0
 *  
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *  
 *  :>
 *
 *****************************************************************************/

/*
 * bbf-xpon.c
 */
#include <bcmos_system.h>
#include <bcmolt_netconf_module_utils.h>
#include <bbf-xpon.h>

#define BBF_XPON_MODULE_NAME                        "bbf-xpon"
#define BBF_XPONVANI_MODULE_NAME                    "bbf-xponvani"
#define BBF_XPON_IFTYPE_MODULE_NAME                 "bbf-xpon-if-type"
#define BBF_XPONGEMTCONT_MODULE_NAME                "bbf-xpongemtcont"
#define BBF_L2_FORWARDING_MODULE_NAME               "bbf-l2-forwarding"
#define BBF_HARDWARE_MODULE_NAME                    "bbf-hardware"
#define BBF_HARDWARE_TYPES_MODULE_NAME              "bbf-hardware-types"
#define BBF_XPON_ONU_STATES_MODULE_NAME             "bbf-xpon-onu-states"
#define BBF_QOS_CLASSIFIERS_MODULE_NAME             "bbf-qos-classifiers"
#define BBF_QOS_POLICIES_MODULE_NAME                "bbf-qos-policies"
#define BBF_LINK_TABLE_MODULE_NAME                  "bbf-link-table"
#define IETF_INTERFACES_MODULE_NAME                 "ietf-interfaces"
#define IETF_HARDWARE_MODULE_NAME                   "ietf-hardware"

#define BBF_XPON_INTERFACE_PATH_BASE                "/ietf-interfaces:interfaces/interface"
#define BBF_XPON_INTERFACE_STATE_PATH_BASE          "/ietf-interfaces:interfaces-state/interface"

#define BCM_SR_MODULE_CHANGE_SUBSCR_FLAGS           SR_SUBSCR_ENABLED | SR_SUBSCR_CTX_REUSE

sr_subscription_ctx_t *sr_ctx;

static const char* ietf_interfaces_features[] = {
    "arbitrary-names",
    "pre-provisioning",
    "if-mib",
    NULL
};

static const char* xponvani_features[] = {
    "configurable-v-ani-onu-id",
    NULL
};

static const char* xpongemtcont_features[] = {
    "configurable-gemport-id",
    "configurable-alloc-id",
    NULL
};

static const char* l2_forwarding_features[] = {
    "forwarding-databases",
    "shared-forwarding-databases",
    "mac-learning",
    "split-horizon-profiles",
    NULL
};

static const char* ietf_hardware_features[] = {
    "entity-mib",
    "hardware-state",
    NULL
};

static const char* bbf_hardware_features[] = {
    "additional-hardware-configuration",
    "model-name-configuration",
    "interface-hardware-reference",
    "hardware-component-reset",
    NULL
};

/* Data store change indication callback */
static int bbf_xpon_change_cb(sr_session_ctx_t *srs, const char *module_name,
    const char *xpath, sr_event_t event, uint32_t request_id, void *private_ctx)
{
    sr_change_iter_t *sr_iter = NULL;
    sr_change_oper_t sr_oper;
    sr_val_t *sr_old_val = NULL, *sr_new_val = NULL;
    char qualified_xpath[256];
    int sr_rc;
    bcmos_errno err = BCM_ERR_OK;

    NC_LOG_INFO("xpath=%s event=%d\n", xpath, event);

    /* We only handle CHANGE and ABORT events.
     * Since there is no way to reserve resources in advance and no way to fail the APPLY event,
     * configuration is applied in VERIFY event.
     * There are no other verifiers, but if there are and they fail,
     * ABORT event will roll-back the changes.
     */
    if (event == SR_EV_DONE)
        return SR_ERR_OK;

    snprintf(qualified_xpath, sizeof(qualified_xpath)-1, "%s//.", xpath);
    qualified_xpath[sizeof(qualified_xpath)-1] = 0;

    for (sr_rc = sr_get_changes_iter(srs, qualified_xpath, &sr_iter);
        (err == BCM_ERR_OK) && (sr_rc == SR_ERR_OK) &&
            (sr_rc = sr_get_change_next(srs, sr_iter, &sr_oper, &sr_old_val, &sr_new_val)) == SR_ERR_OK;
        nc_sr_free_value_pair(&sr_old_val, &sr_new_val))
    {
        NC_LOG_DBG("old_val=%s new_val=%s. Leaf type %d\n",
            sr_old_val ? sr_old_val->xpath : "none",
            sr_new_val ? sr_new_val->xpath : "none",
            sr_old_val ? sr_old_val->type : sr_new_val->type);
    }

    nc_sr_free_value_pair(&sr_old_val, &sr_new_val);
    sr_free_change_iter(sr_iter);

    return SR_ERR_OK;
}

/* Subscribe to configuration change events */
static bcmos_errno bbf_xpon_subscribe(sr_session_ctx_t *srs)
{
    int sr_rc;

    /* subscribe to events */
    sr_rc = sr_module_change_subscribe(srs, IETF_INTERFACES_MODULE_NAME, BBF_XPON_INTERFACE_PATH_BASE,
            bbf_xpon_change_cb, NULL, 0, BCM_SR_MODULE_CHANGE_SUBSCR_FLAGS,
            &sr_ctx);
    if (SR_ERR_OK == sr_rc)
    {
        NC_LOG_INFO("Subscribed to %s subtree changes.\n", BBF_XPON_INTERFACE_PATH_BASE);
    }
    else
    {
        NC_LOG_ERR("Failed to subscribe to %s subtree changes (%s).\n",
            BBF_XPON_INTERFACE_PATH_BASE, sr_strerror(sr_rc));
    }

    return (sr_rc == SR_ERR_OK) ? BCM_ERR_OK : BCM_ERR_INTERNAL;
}

bcmos_errno bbf_xpon_module_init(sr_session_ctx_t *srs, struct ly_ctx *ly_ctx)
{
    bcmos_errno err = BCM_ERR_INTERNAL;
    const struct lys_module *ietf_intf_mod;
    const struct lys_module *xponvani_mod;
    const struct lys_module *xpongemtcont_mod;
    const struct lys_module *l2_forwarding_mod;
    const struct lys_module *ietf_hardware_mod;
    const struct lys_module *bbf_hardware_types_mod;
    const struct lys_module *bbf_hardware_mod;
    const struct lys_module *onu_states_mod;
    int i;

    do  {
        /* make sure that ietf-interfaces module is loaded */
        ietf_intf_mod = ly_ctx_get_module(ly_ctx, IETF_INTERFACES_MODULE_NAME, NULL, 1);
        if (ietf_intf_mod == NULL)
        {
            ietf_intf_mod = ly_ctx_load_module(ly_ctx, IETF_INTERFACES_MODULE_NAME, NULL);
            if (ietf_intf_mod == NULL)
            {
                NC_LOG_ERR(IETF_INTERFACES_MODULE_NAME ": can't find the schema in sysrepo\n");
                break;
            }
        }

        /* make sure that bbf-xponvani module is loaded */
        xponvani_mod = ly_ctx_get_module(ly_ctx, BBF_XPONVANI_MODULE_NAME, NULL, 1);
        if (xponvani_mod == NULL)
        {
            xponvani_mod = ly_ctx_load_module(ly_ctx, BBF_XPONVANI_MODULE_NAME, NULL);
            if (xponvani_mod == NULL)
            {
                NC_LOG_ERR(BBF_XPONVANI_MODULE_NAME ": can't find the schema in sysrepo\n");
                break;
            }
        }

        /* make sure that bbf-xpongemtcont module is loaded */
        xpongemtcont_mod = ly_ctx_get_module(ly_ctx, BBF_XPONGEMTCONT_MODULE_NAME, NULL, 1);
        if (xpongemtcont_mod == NULL)
        {
            xpongemtcont_mod = ly_ctx_load_module(ly_ctx, BBF_XPONGEMTCONT_MODULE_NAME, NULL);
            if (xpongemtcont_mod == NULL)
            {
                NC_LOG_ERR(BBF_XPONGEMTCONT_MODULE_NAME ": can't find the schema in sysrepo\n");
                break;
            }
        }

        /* make sure that bbf-xpongemtcont module is loaded */
        l2_forwarding_mod = ly_ctx_get_module(ly_ctx, BBF_L2_FORWARDING_MODULE_NAME, NULL, 1);
        if (l2_forwarding_mod == NULL)
        {
            l2_forwarding_mod = ly_ctx_load_module(ly_ctx, BBF_L2_FORWARDING_MODULE_NAME, NULL);
            if (l2_forwarding_mod == NULL)
            {
                NC_LOG_ERR(BBF_L2_FORWARDING_MODULE_NAME ": can't find the schema in sysrepo\n");
                break;
            }
        }

        /* make sure that ietf-hardware module is loaded */
        ietf_hardware_mod = ly_ctx_get_module(ly_ctx, IETF_HARDWARE_MODULE_NAME, NULL, 1);
        if (ietf_hardware_mod == NULL)
        {
            ietf_hardware_mod = ly_ctx_load_module(ly_ctx, IETF_HARDWARE_MODULE_NAME, NULL);
            if (ietf_hardware_mod == NULL)
            {
                NC_LOG_ERR(IETF_HARDWARE_MODULE_NAME ": can't find the schema in sysrepo\n");
                break;
            }
        }

        /* make sure that bbf-hardware-types module is loaded */
        bbf_hardware_types_mod = ly_ctx_get_module(ly_ctx, BBF_HARDWARE_TYPES_MODULE_NAME, NULL, 1);
        if (bbf_hardware_types_mod == NULL)
        {
            bbf_hardware_types_mod = ly_ctx_load_module(ly_ctx, BBF_HARDWARE_TYPES_MODULE_NAME, NULL);
            if (bbf_hardware_types_mod == NULL)
            {
                NC_LOG_ERR(BBF_HARDWARE_TYPES_MODULE_NAME ": can't find the schema in sysrepo\n");
                break;
            }
        }

        /* make sure that bbf-hardware module is loaded */
        bbf_hardware_mod = ly_ctx_get_module(ly_ctx, BBF_HARDWARE_MODULE_NAME, NULL, 1);
        if (bbf_hardware_mod == NULL)
        {
            bbf_hardware_mod = ly_ctx_load_module(ly_ctx, BBF_HARDWARE_MODULE_NAME, NULL);
            if (bbf_hardware_mod == NULL)
            {
                NC_LOG_ERR(BBF_HARDWARE_MODULE_NAME ": can't find the schema in sysrepo\n");
                break;
            }
        }

        /* make sure that bbf-xpon-onu-states module is loaded */
        onu_states_mod = ly_ctx_get_module(ly_ctx, BBF_XPON_ONU_STATES_MODULE_NAME, NULL, 1);
        if (onu_states_mod == NULL)
        {
            onu_states_mod = ly_ctx_load_module(ly_ctx, BBF_XPON_ONU_STATES_MODULE_NAME, NULL);
            if (onu_states_mod == NULL)
            {
                NC_LOG_ERR(BBF_XPON_ONU_STATES_MODULE_NAME ": can't find the schema in sysrepo\n");
                break;
            }
        }

        /* Enable all relevant features are enabled in sysrepo */
        for (i = 0; ietf_interfaces_features[i]; i++)
        {
            if (lys_features_enable(ietf_intf_mod, ietf_interfaces_features[i]))
            {
                NC_LOG_ERR("%s: can't enable feature %s\n", IETF_INTERFACES_MODULE_NAME, ietf_interfaces_features[i]);
                break;
            }
        }
        if (ietf_interfaces_features[i])
            break;

        for (i = 0; xponvani_features[i]; i++)
        {
            if (lys_features_enable(xponvani_mod, xponvani_features[i]))
            {
                NC_LOG_ERR("%s: can't enable feature %s\n", BBF_XPONVANI_MODULE_NAME, xponvani_features[i]);
                break;
            }
        }
        if (xponvani_features[i])
            break;

        for (i = 0; xpongemtcont_features[i]; i++)
        {
            if (lys_features_enable(xpongemtcont_mod, xpongemtcont_features[i]))
            {
                NC_LOG_ERR("%s: can't enable feature %s\n", BBF_XPONGEMTCONT_MODULE_NAME, xpongemtcont_features[i]);
                break;
            }
        }
        if (xpongemtcont_features[i])
            break;

        for (i = 0; l2_forwarding_features[i]; i++)
        {
            if (lys_features_enable(l2_forwarding_mod, l2_forwarding_features[i]))
            {
                NC_LOG_ERR("%s: can't enable feature %s\n", BBF_L2_FORWARDING_MODULE_NAME, l2_forwarding_features[i]);
                break;
            }
        }
        if (l2_forwarding_features[i])
            break;

        for (i = 0; ietf_hardware_features[i]; i++)
        {
            if (lys_features_enable(ietf_hardware_mod, ietf_hardware_features[i]))
            {
                NC_LOG_ERR("%s: can't enable feature %s\n", IETF_HARDWARE_MODULE_NAME, ietf_hardware_features[i]);
                break;
            }
        }
        if (ietf_hardware_features[i])
            break;

        for (i = 0; bbf_hardware_features[i]; i++)
        {
            if (lys_features_enable(bbf_hardware_mod, bbf_hardware_features[i]))
            {
                NC_LOG_ERR("%s: can't enable feature %s\n", BBF_HARDWARE_MODULE_NAME, bbf_hardware_features[i]);
                break;
            }
        }
        if (bbf_hardware_features[i])
            break;

        err = bbf_xpon_subscribe(srs);

    } while (0);

    return err;
}

bcmos_errno bbf_xpon_module_start(sr_session_ctx_t *srs, struct ly_ctx *ly_ctx)
{
    return BCM_ERR_OK;
}

void bbf_xpon_module_exit(sr_session_ctx_t *srs, struct ly_ctx *ly_ctx)
{
}
