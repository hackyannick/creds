#pragma once
#include <ntsecapi.h>
#include <credentialprovider.h>

// Felder der Anmeldekachel.
enum FieldId {
    FI_TILEIMAGE = 0,
    FI_TITLE,
    FI_USERNAME,
    FI_PASSWORD,
    FI_OLD_PASSWORD,   // nur sichtbar, wenn das lokale Passwort nicht mehr passt
    FI_RESET_CHECKBOX, // "altes Passwort unbekannt" -> lokales Passwort zurücksetzen
    FI_SUBMIT,
    FI_INFO,           // Hinweis-/Statuszeile
    FI_NUM_FIELDS
};

struct FieldStatePair {
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};
