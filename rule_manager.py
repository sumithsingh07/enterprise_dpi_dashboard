"""
rule_manager.py

Deep Packet Inspection Rule Engine

Responsible for deciding whether a detected application
should be ALLOWED, BLOCKED, LOGGED, or INSPECTED.
"""

import json
from enum import Enum

from dpi_types import AppType


# ==========================================================
# Packet Action
# ==========================================================

class PacketAction(Enum):

    FORWARD = "FORWARD"

    DROP = "DROP"

    LOG_ONLY = "LOG_ONLY"

    INSPECT = "INSPECT"


# ==========================================================
# Rule Manager
# ==========================================================

class RuleManager:

    def __init__(self):

        self.rules = {}

        self.default_action = PacketAction.FORWARD

    # ------------------------------------------------------
    # Add Rule
    # ------------------------------------------------------

    def add_rule(self, application, action):

        if isinstance(action, str):

            action = PacketAction[action.upper()]

        self.rules[application.upper()] = action

    # ------------------------------------------------------
    # Remove Rule
    # ------------------------------------------------------

    def remove_rule(self, application):

        application = application.upper()

        if application in self.rules:

            del self.rules[application]

    # ------------------------------------------------------
    # Clear Rules
    # ------------------------------------------------------

    def clear_rules(self):

        self.rules.clear()

    # ------------------------------------------------------
    # Get Action
    # ------------------------------------------------------

    def get_action(self, application):

    # Convert AppType enum to string
        if isinstance(application, AppType):
          application = application.name

    # Convert string to uppercase
        if isinstance(application, str):
          application = application.upper()

    # Return PacketAction enum
        return self.rules.get(application, self.default_action)
    # ------------------------------------------------------
    # Has Rule
    # ------------------------------------------------------

    def has_rule(self, application):

        if isinstance(application, AppType):
            application = application.name

        if isinstance(application, str):
            application = application.upper()

        return application in self.rules

    # ------------------------------------------------------
    # Count Rules
    # ------------------------------------------------------

    def rule_count(self):

        return len(self.rules)

    # ------------------------------------------------------
    # Change Default Action
    # ------------------------------------------------------

    def set_default_action(self, action):

        if isinstance(action, str):

            action = PacketAction[action.upper()]

        self.default_action = action

    # ------------------------------------------------------
    # Print Rules
    # ------------------------------------------------------

    def print_rules(self):

        print("\n========== DPI RULES ==========")

        if not self.rules:

            print("No Rules Installed")

        else:

            for app, action in sorted(self.rules.items()):

                print(

                    f"{app:20} -> {action.value}"

                )

        print("-------------------------------")

        print(

            "Default Action :",

            self.default_action.value

        )

        print("===============================\n")

    # ------------------------------------------------------
    # Save Rules
    # ------------------------------------------------------

    def save_rules(self, filename="rules.json"):

        data = {

            "default_action": self.default_action.value,

            "rules": {

                app: action.value

                for app, action in self.rules.items()

            }

        }

        with open(filename, "w") as file:

            json.dump(

                data,

                file,

                indent=4

            )

    # ------------------------------------------------------
    # Load Rules
    # ------------------------------------------------------

    def load_rules(self, filename="rules.json"):

        with open(filename, "r") as file:

            data = json.load(file)

        self.default_action = PacketAction(

            data["default_action"]

        )

        self.rules.clear()

        for app, action in data["rules"].items():

            self.rules[app] = PacketAction(action)


# ==========================================================
# Example Rules
# ==========================================================

def install_default_rules(rule_manager):

    rule_manager.add_rule(

        "YOUTUBE",

        PacketAction.DROP

    )

    rule_manager.add_rule(

        "FACEBOOK",

        PacketAction.DROP

    )

    rule_manager.add_rule(

        "INSTAGRAM",

        PacketAction.DROP

    )

    rule_manager.add_rule(

        "TIKTOK",

        PacketAction.DROP

    )

    rule_manager.add_rule(

        "NETFLIX",

        PacketAction.LOG_ONLY

    )

    rule_manager.add_rule(

        "GOOGLE",

        PacketAction.FORWARD

    )

    rule_manager.add_rule(

        "GITHUB",

        PacketAction.FORWARD

    )

    rule_manager.add_rule(

        "MICROSOFT",

        PacketAction.FORWARD

    )


# ==========================================================
# Self Test
# ==========================================================

if __name__ == "__main__":

    rm = RuleManager()

    install_default_rules(rm)

    rm.print_rules()

    print("YOUTUBE ->", rm.get_action("YOUTUBE").value)

    print("GOOGLE  ->", rm.get_action("GOOGLE").value)

    print("UNKNOWN ->", rm.get_action("UNKNOWN").value)

    rm.save_rules()

    print("\nRules saved to rules.json")

    rm2 = RuleManager()

    rm2.load_rules()

    print("\nLoaded Rules")

    rm2.print_rules()