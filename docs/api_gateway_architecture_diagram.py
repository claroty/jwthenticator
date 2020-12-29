# pylint: disable=pointless-statement
from __future__ import absolute_import

from diagrams import Diagram, Cluster

from diagrams.onprem.client import Client
from diagrams.onprem.network import Envoy
from diagrams.onprem.container import Docker
from diagrams.generic.database import SQL
from diagrams.generic.storage import Storage

NUM_CLIENTS = 3
NUM_SQL_SERVICES = 2
NUM_STORAGE_SERVICES = 1


with Diagram("JWThenticator API Gateway Example Architecture"):

    with Cluster("Service Runtime"):
        api_gateway = Envoy("api-gateway")
        services = []
        with Cluster("Secured Endpoints"):
            for i in range(NUM_SQL_SERVICES + NUM_STORAGE_SERVICES):
                services.append(Docker(f"service-{i}"))

        with Cluster("Registry Endpoints"):
            client_registry = Docker("client-registry")

        with Cluster("Unrestricted Endpoints"):
            jwthenticator_external = Docker("external-jwthenticator")

        with Cluster("Internal Services"):
            jwthenticator_internal = Docker("internal-jwthenticator")

        with Cluster("Services Dependencies"):
            jwthenticator_db = SQL("jwthenticator-db")
            services_deps = []
            for i in range(NUM_SQL_SERVICES):
                services_deps.append(SQL(f"service-{i}-db"))
            for i in range(NUM_STORAGE_SERVICES + 1, NUM_STORAGE_SERVICES + NUM_SQL_SERVICES):
                services_deps.append(Storage(f"service-{i}-storage"))

    # Connect clients to api_gateway
    for i in range(NUM_CLIENTS):
        Client(f"client-{i}") >> api_gateway    # pylint: disable=expression-not-assigned

    # Create internal services flow
    for i in range(NUM_SQL_SERVICES + NUM_STORAGE_SERVICES):
        api_gateway >> services[i] >> services_deps[i]

    # Client registry service
    api_gateway >> client_registry >> jwthenticator_internal >> jwthenticator_db

    # JWThenticator service
    api_gateway >> jwthenticator_external << jwthenticator_db
