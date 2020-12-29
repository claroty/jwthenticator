# pylint: disable=pointless-statement
from __future__ import absolute_import

from diagrams import Diagram, Cluster

from diagrams.k8s.network import Ingress
from diagrams.onprem.client import Client
from diagrams.onprem.container import Docker
from diagrams.generic.database import SQL

NUM_CLIENTS = 3
NUM_SECURE_SERVICES = 2


with Diagram("JWThenticator Direct Validation Example Architecture"):

    with Cluster("Service Runtime"):
        ingress = Ingress("ingress")
        services = []

        jwthenticator = Docker("jwthenticator")
        jwthenticator_db = SQL("jwthenticator-db")

        with Cluster("Secured Endpoints"):
            for i in range(NUM_SECURE_SERVICES):
                services.append(Docker(f"service-{i}"))

    # General initial flow
    for i in range(NUM_CLIENTS):
        Client(f"client-{i}") >> ingress    # pylint: disable=expression-not-assigned

    for i in range(NUM_SECURE_SERVICES):
        ingress >> services[i] >> jwthenticator

    # JWThenticator service
    ingress >> jwthenticator
    jwthenticator - jwthenticator_db
