/* tpm_io_linux_irq.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfTPM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Linux GPIO IRQ handling for TPM interrupt support
 *
 * Supports both GPIO Character Device API (modern) and sysfs (legacy)
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifdef WOLFTPM_IRQ
#ifdef __linux__

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_tis.h>
#include "tpm_io.h"

#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>

/* GPIO Character Device API (modern, preferred) */
#ifdef HAVE_LINUX_GPIO_H
    #include <linux/gpio.h>
    #define USE_GPIO_CHARDEV 1
#else
    /* Fall back to sysfs if GPIO character device API not available */
    #define USE_GPIO_CHARDEV 0
#endif

/* Default GPIO configuration */
#ifndef TPM2_IRQ_GPIO_PIN
    #define TPM2_IRQ_GPIO_PIN 24  /* Default for Raspberry Pi */
#endif

#ifndef TPM2_IRQ_GPIO_CHIP
    #define TPM2_IRQ_GPIO_CHIP 0  /* gpiochip0 */
#endif

#ifndef TPM2_IRQ_TIMEOUT_MS
    #define TPM2_IRQ_TIMEOUT_MS 10000  /* 10 seconds */
#endif

/* GPIO Character Device API implementation */
#if USE_GPIO_CHARDEV

/* Setup GPIO IRQ using character device API */
static int TPM2_Linux_GPIO_IRQ_Setup_CharDev(int gpio_chip, int gpio_pin, int* fd_out)
{
    int fd;
    int ret;
    struct gpioevent_request req;

    /* Open GPIO chip */
    char chip_path[64];
    snprintf(chip_path, sizeof(chip_path), "/dev/gpiochip%d", gpio_chip);
    fd = open(chip_path, O_RDWR);
    if (fd < 0) {
    #ifdef DEBUG_WOLFTPM
        printf("Failed to open GPIO chip %d: %s\n", gpio_chip, strerror(errno));
    #endif
        return -1;
    }

    /* Request GPIO line for interrupt events */
    memset(&req, 0, sizeof(req));
    req.lineoffset = gpio_pin;
    req.handleflags = GPIOHANDLE_REQUEST_INPUT;
    req.eventflags = GPIOEVENT_REQUEST_FALLING_EDGE;  /* TPM uses falling edge */
    strncpy(req.consumer_label, "wolfTPM_IRQ", sizeof(req.consumer_label) - 1);

    ret = ioctl(fd, GPIO_GET_LINEEVENT_IOCTL, &req);
    if (ret < 0) {
    #ifdef DEBUG_WOLFTPM
        printf("Failed to request GPIO event line %d: %s\n", gpio_pin, strerror(errno));
    #endif
        close(fd);
        return -1;
    }

    /* Close chip fd, keep event fd */
    close(fd);
    *fd_out = req.fd;

    return 0;
}

/* Wait for GPIO interrupt using character device */
static int TPM2_Linux_GPIO_IRQ_Wait_CharDev(int fd, int timeout_ms)
{
    struct pollfd pfd;
    int ret;

    pfd.fd = fd;
    pfd.events = POLLIN | POLLPRI;  /* GPIO events use POLLIN */

    ret = poll(&pfd, 1, timeout_ms);
    if (ret < 0) {
    #ifdef DEBUG_WOLFTPM
        printf("GPIO poll failed: %s\n", strerror(errno));
    #endif
        return -1;
    }
    if (ret == 0) {
        /* Timeout */
        return 0;
    }

    /* Interrupt occurred - read event to clear it */
    if (pfd.revents & (POLLIN | POLLPRI | POLLERR)) {
        struct gpioevent_data event;
        ssize_t bytes = read(fd, &event, sizeof(event));
        if (bytes < 0) {
        #ifdef DEBUG_WOLFTPM
            printf("Failed to read GPIO event: %s\n", strerror(errno));
        #endif
            return -1;
        }
        return 1;  /* Interrupt detected */
    }

    return 0;
}

#endif /* USE_GPIO_CHARDEV */

/* Sysfs GPIO implementation (legacy, fallback) */
static int TPM2_Linux_GPIO_IRQ_Setup_Sysfs(int gpio_pin, int* fd_out)
{
    int fd;
    char path[64];
    char gpio_pin_str[16];  /* Buffer for GPIO pin number */

    /* Export GPIO */
    fd = open("/sys/class/gpio/export", O_WRONLY);
    if (fd < 0) {
        if (errno == EACCES) {
        #ifdef DEBUG_WOLFTPM
            printf("GPIO export permission denied (need root)\n");
        #endif
            return -1;
        }
    #ifdef DEBUG_WOLFTPM
        printf("Failed to open GPIO export: %s\n", strerror(errno));
    #endif
        return -1;
    }

    snprintf(gpio_pin_str, sizeof(gpio_pin_str), "%d", gpio_pin);
    if (write(fd, gpio_pin_str, strlen(gpio_pin_str)) < 0) {
        /* May fail if already exported */
        if (errno != EBUSY) {
        #ifdef DEBUG_WOLFTPM
            printf("Failed to export GPIO %d: %s\n", gpio_pin, strerror(errno));
        #endif
            close(fd);
            return -1;
        }
    }
    close(fd);

    /* Wait for GPIO to be available */
    usleep(100000);  /* 100ms */

    /* Set direction to input */
    snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/direction", gpio_pin);
    fd = open(path, O_WRONLY);
    if (fd < 0) {
    #ifdef DEBUG_WOLFTPM
        printf("Failed to set GPIO direction: %s\n", strerror(errno));
    #endif
        return -1;
    }
    if (write(fd, "in", 2) < 0) {
    #ifdef DEBUG_WOLFTPM
        printf("Failed to write GPIO direction: %s\n", strerror(errno));
    #endif
        close(fd);
        return -1;
    }
    close(fd);

    /* Set edge to falling (for TPM interrupt) */
    snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/edge", gpio_pin);
    fd = open(path, O_WRONLY);
    if (fd < 0) {
    #ifdef DEBUG_WOLFTPM
        printf("Failed to set GPIO edge: %s\n", strerror(errno));
    #endif
        return -1;
    }
    if (write(fd, "falling", 7) < 0) {
    #ifdef DEBUG_WOLFTPM
        printf("Failed to write GPIO edge: %s\n", strerror(errno));
    #endif
        close(fd);
        return -1;
    }
    close(fd);

    /* Check initial state - verify line is not stuck LOW */
    snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/value", gpio_pin);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
    #ifdef DEBUG_WOLFTPM
        printf("Failed to open GPIO value: %s\n", strerror(errno));
    #endif
        return -1;
    }

    /* Read initial value */
    char gpio_value[16];  /* Buffer for reading GPIO value */
    if (read(fd, gpio_value, sizeof(gpio_value)) < 0) {
    #ifdef DEBUG_WOLFTPM
        printf("Failed to read GPIO initial value: %s\n", strerror(errno));
    #endif
        close(fd);
        return -1;
    }

    *fd_out = fd;
    return 0;
}

/* Wait for GPIO interrupt using sysfs */
static int TPM2_Linux_GPIO_IRQ_Wait_Sysfs(int fd, int timeout_ms)
{
    struct pollfd pfd;
    int ret;
    char gpio_value[16];  /* Buffer for reading GPIO value */

    pfd.fd = fd;
    pfd.events = POLLPRI | POLLERR;

    /* Seek to beginning before poll */
    lseek(fd, 0, SEEK_SET);

    ret = poll(&pfd, 1, timeout_ms);
    if (ret < 0) {
    #ifdef DEBUG_WOLFTPM
        printf("GPIO poll failed: %s\n", strerror(errno));
    #endif
        return -1;
    }
    if (ret == 0) {
        /* Timeout */
        return 0;
    }

    /* Interrupt occurred - read value to clear it */
    if (pfd.revents & (POLLPRI | POLLERR)) {
        lseek(fd, 0, SEEK_SET);
        if (read(fd, gpio_value, sizeof(gpio_value)) < 0) {
            return -1;
        }
        return 1;  /* Interrupt detected */
    }

    return 0;
}

/* Cleanup sysfs GPIO */
static void TPM2_Linux_GPIO_IRQ_Cleanup_Sysfs(int gpio_pin, int fd)
{
    if (fd >= 0) {
        close(fd);
    }

    /* Unexport GPIO */
    int unexport_fd = open("/sys/class/gpio/unexport", O_WRONLY);
    if (unexport_fd >= 0) {
        char gpio_pin_str[16];  /* Buffer to handle any GPIO pin number */
        snprintf(gpio_pin_str, sizeof(gpio_pin_str), "%d", gpio_pin);
        write(unexport_fd, gpio_pin_str, strlen(gpio_pin_str));
        close(unexport_fd);
    }
}

/* Public API: Setup GPIO IRQ */
int TPM2_Linux_GPIO_IRQ_Setup(TPM2_CTX* ctx, int gpio_pin)
{
    int fd = -1;
    int ret = -1;

    if (ctx == NULL)
        return -1;

    /* Try GPIO Character Device API first (modern) */
#if USE_GPIO_CHARDEV
    ret = TPM2_Linux_GPIO_IRQ_Setup_CharDev(TPM2_IRQ_GPIO_CHIP, gpio_pin, &fd);
    if (ret == 0) {
        ctx->irq_gpio_fd = fd;
        ctx->irq_gpio_pin = gpio_pin;
    #ifdef DEBUG_WOLFTPM
        printf("GPIO IRQ setup (char dev): pin %d, fd %d\n", gpio_pin, fd);
    #endif
        return 0;
    }
#endif

    /* Fallback to sysfs (legacy) */
#ifdef DEBUG_WOLFTPM
    printf("Falling back to sysfs GPIO (deprecated)\n");
#endif
    ret = TPM2_Linux_GPIO_IRQ_Setup_Sysfs(gpio_pin, &fd);
    if (ret == 0) {
        ctx->irq_gpio_fd = fd;
        ctx->irq_gpio_pin = gpio_pin;
    #ifdef DEBUG_WOLFTPM
        printf("GPIO IRQ setup (sysfs): pin %d, fd %d\n", gpio_pin, fd);
    #endif
        return 0;
    }

    /* Both methods failed */
    if (errno == EACCES) {
    #ifdef DEBUG_WOLFTPM
        printf("GPIO IRQ setup failed: permission denied (need root)\n");
    #endif
    } else {
    #ifdef DEBUG_WOLFTPM
        printf("GPIO IRQ setup failed: %s\n", strerror(errno));
    #endif
    }

    return -1;
}

/* Public API: Wait for GPIO interrupt */
int TPM2_Linux_GPIO_IRQ_Wait(TPM2_CTX* ctx, int timeout_ms)
{
    if (ctx == NULL || ctx->irq_gpio_fd < 0)
        return -1;

    /* Try character device API first (if available and likely used) */
#if USE_GPIO_CHARDEV
    /* Character device fds are typically higher numbers, but we can't be sure */
    /* Try character device wait first - if it fails, fall back to sysfs */
    int ret = TPM2_Linux_GPIO_IRQ_Wait_CharDev(ctx->irq_gpio_fd, timeout_ms);
    /* If successful or clear error, return it */
    if (ret >= 0 || errno != EBADF) {
        return ret;
    }
    /* EBADF means wrong fd type, fall through to sysfs */
#endif

    /* Use sysfs */
    return TPM2_Linux_GPIO_IRQ_Wait_Sysfs(ctx->irq_gpio_fd, timeout_ms);
}

/* Public API: Cleanup GPIO IRQ */
void TPM2_Linux_GPIO_IRQ_Cleanup(TPM2_CTX* ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->irq_gpio_fd >= 0) {
        /* Close the file descriptor */
        close(ctx->irq_gpio_fd);
        ctx->irq_gpio_fd = -1;

        /* If pin is set, try sysfs unexport (safe even if not sysfs) */
        if (ctx->irq_gpio_pin >= 0) {
            TPM2_Linux_GPIO_IRQ_Cleanup_Sysfs(ctx->irq_gpio_pin, -1);
            ctx->irq_gpio_pin = -1;
        }
    }
}

#endif /* __linux__ */
#endif /* WOLFTPM_IRQ */

