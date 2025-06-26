"""An Azure RM Python Pulumi program"""

import pulumi
import pulumi_azure_native as azure_native
from pulumi_azure_native import storage
from pulumi_azure_native import resources
import pulumi_azure_native_network_v20230201 as azure_native_network_v20230201

import base64

with open("./key/output.pfx", "rb") as cert_file:

    binary_file_data = cert_file.read()
    base64_encoded_data = base64.b64encode(binary_file_data)
    base64_output = base64_encoded_data.decode('utf-8')

# Create an Azure Resource Group
resource_group = resources.ResourceGroup("resource_group")



vnet = azure_native.network.VirtualNetwork("vnet",
    address_space={
        "address_prefixes": ["10.1.0.0/16"],
    },
    resource_group_name=resource_group.name)

subnet = azure_native.network.Subnet("subnet",
                                     resource_group_name=resource_group.name,
                                     virtual_network_name=vnet.name,
                                    address_prefix="10.1.0.0/24",
                                    private_endpoint_network_policies=azure_native.network.VirtualNetworkPrivateEndpointNetworkPolicies.DISABLED,
                                    private_link_service_network_policies=azure_native.network.VirtualNetworkPrivateLinkServiceNetworkPolicies.ENABLED,
                                     )

azure_native_network_v20230201.network.ApplicationGateway(
            "mygw",
            application_gateway_name="pk-appgw-2",
            backend_address_pools=[
                azure_native_network_v20230201.network.ApplicationGatewayBackendAddressPoolArgs(
                    name="backendAddressPool1",
                ),
            ],
            backend_http_settings_collection=[
                azure_native_network_v20230201.network.ApplicationGatewayBackendHttpSettingsArgs(
                    name="httpsettings1",
                    affinity_cookie_name="ApplicationGatewayAffinity",
                    authentication_certificates=[
                        azure_native_network_v20230201.network.SubResourceArgs(
                            id="$self/sslCertificates/testappgw.example.com",
                        ),
                    ],
                    connection_draining=azure_native_network_v20230201.network.ApplicationGatewayConnectionDrainingArgs(
                        enabled=True,
                        drain_timeout_in_sec=60,
                    ),
                    cookie_based_affinity=azure_native_network_v20230201.network.ApplicationGatewayCookieBasedAffinity.ENABLED,
                    host_name="testing.example.com",
                    pick_host_name_from_backend_address=False,
                    protocol=azure_native_network_v20230201.network.ApplicationGatewayProtocol.HTTPS,
                    port=443,
                    request_timeout=20,
                    probe=azure_native_network_v20230201.network.SubResourceArgs(
                        id="$self/probes/probe1"
                    ),
                ),
            ],
            enable_http2=True,
            frontend_ip_configurations=[
                azure_native_network_v20230201.network.ApplicationGatewayFrontendIPConfigurationArgs(
                    name="frontendIPConfig1",
                    subnet=azure_native_network_v20230201.network.SubResourceArgs(
                        id=subnet.id,
                    ),
                    # this was one of the things the pipeline complained about - on the current sku we have to have a static IP Address defined here.
                    private_ip_allocation_method=azure_native_network_v20230201.network.IPAllocationMethod.STATIC,
                    private_ip_address="10.1.2.3"
                ),
            ],
            frontend_ports=[
                azure_native_network_v20230201.network.ApplicationGatewayFrontendPortArgs(
                    name="port1",
                    port=443,
                ),
            ],
            gateway_ip_configurations=[
                azure_native_network_v20230201.network.ApplicationGatewayIPConfigurationArgs(
                    name="subnet1",
                    subnet=azure_native_network_v20230201.network.SubResourceArgs(
                        id=subnet.id,
                    ),
                ),
            ],
            http_listeners = [
                azure_native_network_v20230201.network.ApplicationGatewayHttpListenerArgs(
                    name="httplistener1",
                    protocol=azure_native_network_v20230201.network.ApplicationGatewayProtocol.HTTPS,
                    frontend_ip_configuration=azure_native_network_v20230201.network.SubResourceArgs(
                        id="$self/frontendIPConfigurations/frontendIPConfig1",
                    ),
                    frontend_port=azure_native_network_v20230201.network.SubResourceArgs(
                        id="$self/frontendPorts/port1",
                    ),
                    require_server_name_indication=False,
                    ssl_certificate=azure_native_network_v20230201.network.SubResourceArgs(
                        id="$self/sslCertificates/testappgw.rlicorp.com"
                    )
                ),
            ],
            resource_group_name=resource_group.name,
            request_routing_rules=[
                azure_native_network_v20230201.network.ApplicationGatewayRequestRoutingRuleArgs(
                    name="routingRule1",
                    rule_type=azure_native_network_v20230201.network.ApplicationGatewayRequestRoutingRuleType.BASIC,
                    http_listener=azure_native_network_v20230201.network.SubResourceArgs(
                        id = "$self/httpListeners/httplistener1",
                    ),
                    backend_address_pool=azure_native_network_v20230201.network.SubResourceArgs(
                        id="$self/backendAddressPools/backendAddressPool1",
                    ),
                    backend_http_settings=azure_native_network_v20230201.network.SubResourceArgs(
                        id="$self/backendHttpSettingsCollection/httpsettings1",
                    ),
                    priority=10,
                ),
            ],
            sku=azure_native_network_v20230201.network.ApplicationGatewaySkuArgs(
                name=azure_native.network.ApplicationGatewaySkuName.STANDARD_V2,
                tier=azure_native.network.ApplicationGatewayTier.STANDARD_V2,
                capacity=2,
            ),
            probes=[
                azure_native_network_v20230201.network.ApplicationGatewayProbeArgs(
                    protocol=azure_native_network_v20230201.network.ApplicationGatewayProtocol.HTTPS,
                    host="testthething,example.com",
                    path="/",
                    name="probe1",
                    unhealthy_threshold=3,
                    interval=30,
                    timeout=30,
                ),
            ],
            ssl_certificates=[
                azure_native_network_v20230201.network.ApplicationGatewaySslCertificateArgs(
                    name = "testappgw.example.com",
                    data = base64_output,
                    password="1234"
                )
            ],
            ssl_profiles=[
                azure_native_network_v20230201.network.ApplicationGatewaySslProfileArgs(
                    name="routing-nc-dev-ssl-profile",
                    ssl_policy=azure_native_network_v20230201.network.ApplicationGatewaySslPolicyArgs(
                        policy_name=azure_native_network_v20230201.network.ApplicationGatewaySslPolicyName.APP_GW_SSL_POLICY20220101,
                        policy_type=azure_native_network_v20230201.network.ApplicationGatewaySslPolicyType.PREDEFINED,
                    )
                )
            ],
        )