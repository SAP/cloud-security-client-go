# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
#
# SPDX-License-Identifier: Apache-2.0

GO=go
GOBUILD=$(GO) build
GOCLEAN=$(GO) clean
GOTEST=$(GO) test
GOGET=$(GO) get
GOVET=$(GO) vet
GOLIST=$(GO) list

GOBUILD_FLAGS=-v
GOTEST_FLAGS=-v
GOGET_FLAGS=-v

.PHONY: help build get-deps test lint vet pull-request clean

help:
	@echo "Makefile for SAP/cloud-security-client-go"
	@echo ""
	@echo "Usage:"
	@echo ""
	@echo "	make <commands>"
	@echo ""
	@echo "The commands are:"
	@echo ""
	@echo "	build               Build the package"
	@echo "	clean               Run go clean"
	@echo "	help                Print this help text"
	@echo "	get-deps            Download the dependencies"
	@echo "	lint                Run golangci-lint"
	@echo "	pull-request        Run all tests required for a PR"
	@echo "	test                Run go test"
	@echo "	vet                 Run go vet"

build: get-deps
	$(GOBUILD) $(GOBUILD_FLAGS) ./...

get-deps:
	$(GOGET) $(GOGET_FLAGS) -t -d ./...

test:
	$(GOTEST) $(GOTEST_FLAGS) --tags unit ./...

lint:
	golangci-lint run

vet:
	$(GOVET) ./...

pull-request: GOBUILD_FLAGS=
pull-request: GOGET_FLAGS=
pull-request: GOTEST_FLAGS=
pull-request: build test vet lint
	@echo ""
	@echo "------------------------------------------------------"
	@echo ""
	@echo "You can submit your work to "
	@echo "github.com/SAP/cloud-security-client-go/pulls"
	@echo ""
	@echo "Thank you!"

clean:
	@$(GOCLEAN)
