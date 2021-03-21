#!/usr/bin/env python3

from aws_cdk import core

from cdk_bug_test.cdk_bug_test_stack import CdkBugTestStack


app = core.App()
CdkBugTestStack(app, "cdk-bug-test")

app.synth()
