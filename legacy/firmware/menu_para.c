#include "menu_para.h"
#include <stdbool.h>
#include "ble.h"
#include "config.h"
#include "gettext.h"
#include "protect.h"
#include "util.h"

extern uint8_t ui_language;

char* format_time(uint32_t ms) {
  static char line[sizeof("4294967296 minutes?")] = {0};

  const char* unit = _(O__HOUR);

  if (ms == 0) {
    return _(O__NEVER);
  }
  uint32_t num = ms / 1000U;

  if (ms >= 60 * 60 * 1000) {
    unit = _(O__HOUR);
    num /= 60 * 60U;
  } else if (ms >= 60 * 1000) {
    unit = _(O__MINUTE);
    num /= 60U;
  }

  uint2str(num, line);
  strlcat(line, " ", sizeof(line));
  strlcat(line, unit, sizeof(line));
  if (num > 1 && ui_language == 0) {
    strlcat(line, "s", sizeof(line));
  }
  return line;
}

char* menu_para_ble_state(void) {
  return ble_get_switch() ? _(O__ENABLED) : _(O__DISABLED);
}

char* menu_para_language(void) { return (char*)i18n_langs[ui_language]; }

char* menu_para_shutdown(void) {
  return format_time(config_getAutoLockDelayMs());
}

char* menu_para_autolock(void) { return format_time(config_getSleepDelayMs()); }

char* menu_para_passphrase(void) {
  bool passphrase_protection = false;
  config_getPassphraseProtection(&passphrase_protection);
  return passphrase_protection ? _(O__ENABLED) : _(O__DISABLED);
};

char* menu_para_trezor_comp_mode_state(void) {
  bool trezor_comp_mode_current = false;
  config_getTrezorCompMode(&trezor_comp_mode_current);
  return trezor_comp_mode_current ? _(O__ENABLED) : _(O__DISABLED);
}

char* menu_para_safety_checks_state(void) {
  SafetyCheckLevel safetyCheckLevel = config_getSafetyCheckLevel();
  if (safetyCheckLevel == SafetyCheckLevel_Strict) return _(O__ON);
  return _(O__OFF);
}

int menu_para_ble_index(void) { return ble_get_switch() ? 0 : 1; }

int menu_para_language_index(void) { return ui_language; }

int menu_para_shutdown_index(void) {
  int ms = config_getAutoLockDelayMs();
  if (ms == 1 * 60 * 1000) {
    return 0;
  } else if (ms == 3 * 60 * 1000) {
    return 1;
  } else if (ms == 5 * 60 * 1000) {
    return 2;
  } else if (ms == 10 * 60 * 1000) {
    return 3;
  } else if (ms == 0) {
    return 4;
  }

  return 0;
}

int menu_para_autolock_index(void) {
  int ms = config_getSleepDelayMs();
  if (ms == 1 * 60 * 1000) {
    return 0;
  } else if (ms == 2 * 60 * 1000) {
    return 1;
  } else if (ms == 5 * 60 * 1000) {
    return 2;
  } else if (ms == 10 * 60 * 1000) {
    return 3;
  } else if (ms == 0) {
    return 4;
  } else {
    return 5;
  }

  return 0;
}

int menu_para_passphrase_index(void) {
  bool passphrase_protection = false;
  config_getPassphraseProtection(&passphrase_protection);
  return passphrase_protection ? 0 : 1;
}

int menu_para_trezor_comp_mode_index(void) {
  bool trezor_comp_mode_current = false;
  config_getTrezorCompMode(&trezor_comp_mode_current);
  return trezor_comp_mode_current ? 0 : 1;
}

int menu_para_safety_checks_index(void) {
  SafetyCheckLevel safetyCheckLevel = config_getSafetyCheckLevel();
  if (safetyCheckLevel == SafetyCheckLevel_Strict) return 0;
  return 1;
}

void menu_para_set_ble(int index) {
  bool ble_state = index ? false : true;
  if (ble_state != ble_get_switch()) {
    change_ble_sta(ble_state);
  }
}

void menu_para_set_language(int index) {
  if (ui_language != index) config_setLanguage(i18n_lang_keys[index]);
}

void menu_para_set_shutdown(int index) {
  uint32_t ms[5] = {1 * 60 * 1000, 3 * 60 * 1000, 5 * 60 * 1000, 10 * 60 * 1000,
                    0};
  config_setAutoLockDelayMs(ms[index]);
}

void menu_para_set_sleep(int index) {
  uint32_t ms[5] = {60 * 1000, 2 * 60 * 1000, 5 * 60 * 1000, 10 * 60 * 1000, 0};
  config_setSleepDelayMs(ms[index]);
}

char* menu_para_usb_lock(void) {
  bool lock = false;
  config_getUsblock(&lock, true);
  return lock ? _(O__ENABLED) : _(O__DISABLED);
};

int menu_para_usb_lock_index(void) {
  bool lock = false;
  config_getUsblock(&lock, true);
  return lock ? 0 : 1;
}

char* menu_para_input_direction(void) {
  bool d = false;
  config_getInputDirection(&d);
  return d ? _(O__REVERSE) : _(O__DEFAULT);
};

int menu_para_input_direction_index(void) {
  bool d = false;
  config_getInputDirection(&d);
  return d ? 1 : 0;
}
