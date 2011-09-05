#include <linux/types.h>
#include <linux/errno.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <asm/signal.h>
#include <mach/gpio.h>
#include <linux/delay.h>
#include <linux/MCU_IR.h>
#include <mach/msm_smd.h> //Div2D5-OwenHuang-SF5_IR_MCU_Settings-02+

static struct platform_device *sensor_pdev = NULL;
static struct ir_mcu mcu_gpio_data;

//Div2D5-OwenHuang-SF5_IR_MCU_Settings-02+{
#define PHASE_ID fih_get_product_phase()
#define PHASE_ID_IS_PR1 (fih_get_product_phase() == Product_PR1)
//Div2D5-OwenHuang-SF5_IR_MCU_Settings-02+}

//Div2D5-OwenHuang-SF5_CIR_GPIOSetting-01+{
#define VALID_GPIO(gpio) ((gpio == 0xFF) ? 0:1)
static int request_config_gpio(unsigned int gpio_number, unsigned int pull_up_down)
{
	int ret;
	DBG_MSG("%s", __func__);

	ret = gpio_request(gpio_number ,"");
	if (ret)
	{
		ERR_MSG("GPIO tlmm GPIO_%d failed!", gpio_number);
		return (-EIO);
	}

	ret = gpio_tlmm_config(GPIO_CFG(gpio_number, 0, GPIO_CFG_OUTPUT, pull_up_down, GPIO_CFG_2MA), GPIO_CFG_ENABLE);
	if (ret)
	{
		ERR_MSG("GPIO tlmm GPIO_%d failed!", gpio_number);
		return (-EIO);
	}

	return 0;
}

static int config_cir_gpio(void)
{
	DBG_MSG("%s", __func__);
	INF_MSG("phase id(%d)", PHASE_ID);

	if (PHASE_ID == Product_PR1)
	{
		mcu_gpio_data.mcu_buad  = MCU_IR_BAUD_RATE_PIN;
		mcu_gpio_data.mcu_rst_n = MCU_IR_RESET_PIN; 
		mcu_gpio_data.mcu_level_shift = 0xFF; // no use
	}
	else if (PHASE_ID >= Product_PR1p5 && PHASE_ID <= Product_PR2)
	{
		mcu_gpio_data.mcu_buad  = 0xFF; //no use
		mcu_gpio_data.mcu_rst_n = MCU_IR_RESET_PIN; 
		mcu_gpio_data.mcu_level_shift = MCU_LEVEL_SHIFT_EN;
	}
	else if (PHASE_ID > Product_PR2)
	{
		mcu_gpio_data.mcu_buad  = 0xFF; //no use
		mcu_gpio_data.mcu_rst_n = MCU_IR_RESET_PIN; 
		mcu_gpio_data.mcu_level_shift = MCU_LEVEL_SHIFT_EN_PCR;
	}

	INF_MSG("GPIO_Baud = %d, GPIO_rst_n = %d, GPIO_level_shift_en = %d", 
		mcu_gpio_data.mcu_buad, mcu_gpio_data.mcu_rst_n, mcu_gpio_data.mcu_level_shift);

	//setup and configure GPIO
	if (VALID_GPIO(mcu_gpio_data.mcu_buad))//config baud rate pin
	{
		if (request_config_gpio(mcu_gpio_data.mcu_buad, GPIO_CFG_PULL_DOWN))
			return -EIO;
	}

	if (VALID_GPIO(mcu_gpio_data.mcu_rst_n))//config rest_n pin
	{
		if (request_config_gpio(mcu_gpio_data.mcu_rst_n, GPIO_CFG_PULL_DOWN))
			return -EIO;
	}

	if (VALID_GPIO(mcu_gpio_data.mcu_level_shift))//config level shift pin
	{
		if (request_config_gpio(mcu_gpio_data.mcu_level_shift, GPIO_CFG_PULL_UP))
			return -EIO;
	}

	return 0;
}
//Div2D5-OwenHuang-SF5_CIR_GPIOSetting-01+}

static int ir_mcu_open(struct inode *inode, struct file *file)
{
	DBG_MSG("%s", __func__);
	return 0;
}

static int ir_mcu_release(struct inode *inode, struct file *file)
{
	DBG_MSG("%s", __func__);
	return 0;
}

static int ir_mcu_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
	DBG_MSG("%s, cmd = %d", __func__, cmd);

	//Div2D5-OwenHuang-SF5_IR_MCU_Settings-02*{
	if (PHASE_ID_IS_PR1)
	{
		switch(cmd)
		{
			case MCU_RESET_CMD:
				gpio_set_value(mcu_gpio_data.mcu_rst_n, 0);
				msleep(200);
				gpio_set_value(mcu_gpio_data.mcu_rst_n, 1);
				break;

			case MCU_BAUD_9600:
				gpio_set_value(mcu_gpio_data.mcu_buad, 1);
				break;

			case MCU_BAUD_192000:
				gpio_set_value(mcu_gpio_data.mcu_buad, 0);
				break;
			
			default:
				INF_MSG("the command is not supported NOW!");
				break;
		}
	}
	else
	{
		switch(cmd)
		{
			case MCU_RESET_CMD:
				gpio_set_value(mcu_gpio_data.mcu_rst_n, 0);
				msleep(200);
				gpio_set_value(mcu_gpio_data.mcu_rst_n, 1);
				break;

			case MCU_LEVEL_ENABLE:
				gpio_set_value(mcu_gpio_data.mcu_level_shift, 1); //Div2D5-OwenHuang-SF5_CIR_GPIOSetting-00*
				break;
				
			case MCU_LEVEL_DISABLE:
				gpio_set_value(mcu_gpio_data.mcu_level_shift, 0); //Div2D5-OwenHuang-SF5_CIR_GPIOSetting-00*
				break;		
			
			default:
				INF_MSG("the command is not supported NOW!");
				break;
		}
	}
	//Div2D5-OwenHuang-SF5_IR_MCU_Settings-02*}

	DBG_MSG("GPIO_mcu_rst_n(%d), GPIO_mcu_baud(%d)", gpio_get_value(mcu_gpio_data.mcu_rst_n), 
		gpio_get_value(mcu_gpio_data.mcu_buad));
	
	return 0;
}

static struct file_operations uv_sensor_fops = {
    .open    = ir_mcu_open,
    .release = ir_mcu_release,
    .ioctl   = ir_mcu_ioctl,
};

static struct miscdevice ir_mcu_dev = {
    MISC_DYNAMIC_MINOR,
    "ir_mcu",
    &uv_sensor_fops
};

static int sensor_resume(struct platform_device *pdev)
{
	INF_MSG("%s", __func__);
	return 0;
}

static int sensor_suspend(struct platform_device *pdev, pm_message_t state)
{
	INF_MSG("%s", __func__);
	return 0;
}
	
static int sensor_remove(struct platform_device *pdev)
{
	INF_MSG("%s", __func__);
	return 0;
}

static int __init sensor_probe(struct platform_device *pdev)
{
	int ret;
	INF_MSG("%s", __func__);

	//Div2D5-OwenHuang-SF5_CIR_GPIOSetting-01+{
	ret = config_cir_gpio();
	if (ret)
	{
		ERR_MSG("Setup CIR gpio failed!");
		return -EIO;
	}

	if (VALID_GPIO(mcu_gpio_data.mcu_level_shift))
		gpio_set_value(mcu_gpio_data.mcu_level_shift, 1); //enable level shift pin
	//Div2D5-OwenHuang-SF5_CIR_GPIOSetting-01+}

	//reset mcu
	gpio_direction_output(mcu_gpio_data.mcu_rst_n, 0);
	msleep(200);
	gpio_direction_output(mcu_gpio_data.mcu_rst_n, 1);

	ret = misc_register(&ir_mcu_dev);
	
	return ret;
}

static struct platform_driver ir_mcu_driver = {
	.probe		= sensor_probe,
	.remove		= sensor_remove,
	.suspend    = sensor_suspend,
	.resume     = sensor_resume,
	.driver		= {
		.name = "ir_mcu",
	},
};

static int __init ir_mcu_init(void)
{
	INF_MSG("%s", __func__);
	sensor_pdev = platform_device_register_simple("ir_mcu", 0, NULL, 0);
    if (IS_ERR(sensor_pdev)) {
        return -1;
    }
	return platform_driver_register(&ir_mcu_driver);
}

static void  __exit ir_mcu_exit(void)
{	
	INF_MSG("%s", __func__);
	platform_driver_unregister(&ir_mcu_driver);
	platform_device_unregister(sensor_pdev);
}

module_init(ir_mcu_init);
module_exit(ir_mcu_exit);

MODULE_DESCRIPTION("IR MCU Sensor Linux Driver v1.0");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("owenhuang@fihspec.com");
MODULE_VERSION("Version 1.0");
MODULE_ALIAS("platform:msm7X30");

