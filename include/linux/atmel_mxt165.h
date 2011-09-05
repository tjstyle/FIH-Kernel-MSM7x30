#ifndef _atmel_mxt165_h_
#define _atmel_mxt165_h_

#ifndef CONFIG_FIH_FTM
#define ATMEL_MXT165_MT
#endif

#define GPIO_TP_INT_N               42
#define GPIO_TP_RST_N               56
#define DEFAULT_REG_NUM             64

#define MSB(uint16_t)  (((uint8_t* )&uint16_t)[1])
#define LSB(uint16_t)  (((uint8_t* )&uint16_t)[0])

#define TOUCH_DEVICE_NAME           "atmel_mxt165"
#define TOUCH_DEVICE_VREG           "gp9"
#define TOUCH_DEVICE_I2C_ADDRESS    0x4Au

#define LOW                         0
#define HIGH                        1
#define FALSE                       0
#define TRUE                        1

#define TS_MAX_POINTS               5	//Div2-D5-Peripheral-FG-TouchAddto5Multitouch-00*
#define TS_MAX_X                    1023
#define TS_MIN_X                    0
#define TS_MIN_Y                    0

#define TS_MAX_KEYS                 4	//Div2-D5-Peripheral-FG-TouchAddNewPhase-00+
#define TS_KEY1_X                   256
#define TS_KEY2_X                   512
#define TS_KEY3_X                   768
#define TS_KEY4_X                   1023

#define DB_LEVEL0                   0
#define DB_LEVEL1                   1
#define DB_LEVEL2                   2
#define TCH_DBG(level, message, ...) \
    do { \
        if ((level) <= mxt_debug_level) \
            printk("[TOUCH] %s : " message "\n", __FUNCTION__, ## __VA_ARGS__); \
    } while (0)
#define TCH_ERR(msg, ...) printk("[TOUCH_ERR] %s : " msg "\n", __FUNCTION__, ## __VA_ARGS__)
#define TCH_MSG(msg, ...) printk("[TOUCH] " msg "\n", ## __VA_ARGS__)

struct point_info {
    int x;
    int y;
    int num;
    int first_area;
    int last_area;
};

//Div2-D5-Peripheral-FG-TouchAddNewPhase-00+[
struct dynamic_info {
    int TS_PHASE;
    int TS_MAX_Y;
};
//Div2-D5-Peripheral-FG-TouchAddNewPhase-00+]

struct atmel_mxt165_info {
    struct dynamic_info dynamic;	//Div2-D5-Peripheral-FG-TouchAddNewPhase-00+
#ifdef CONFIG_HAS_EARLYSUSPEND
    struct early_suspend early_suspended;
#endif
    struct i2c_client *client;
    struct input_dev *touch_input;
    struct input_dev *key_input;
    struct point_info points[TS_MAX_POINTS];
    struct work_struct work_queue;
    int first_finger_id;
    bool fake_proximity;
    bool suspend_state;
    bool key_state[TS_MAX_KEYS];	//Div2-D5-Peripheral-FG-TouchAddNewPhase-00+
    uint8_t T7[3];
} *atmel_mxt165;

enum ts_state {
    NO_TOUCH = 0,
    PRESS_TOUCH_AREA,
    PRESS_KEY1_AREA,
    PRESS_KEY2_AREA,
    PRESS_KEY3_AREA,
    PRESS_KEY4_AREA
};

//Div2-D5-Peripheral-FG-TouchAddNewPhase-00+[
enum ts_phase {
    TOUCH_PHASE1 = 0,
    TOUCH_PHASE2,
    TOUCH_PHASE3
};
//Div2-D5-Peripheral-FG-TouchAddNewPhase-00+]

#ifdef CONFIG_HAS_EARLYSUSPEND
void atmel_mxt165_early_suspend(struct early_suspend *h);
void atmel_mxt165_late_resume(struct early_suspend *h);
#endif

#endif
