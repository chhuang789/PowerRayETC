import os, time, sys

FAN_GPIO = ['73', '74', '75', '76']
#FAN_GPIO = ['476', '477', '478', '479']
OUTPUT_FILE = '/tmp/fanspeed_detected'


class FanSpeedDetector:
    def __init__(self, sampling_times=2000):
        self._initial_gpio()
        self.sampling_times = sampling_times

    @staticmethod
    def _initial_gpio():
        for gpio in FAN_GPIO:
            if not os.path.exists("/sys/class/gpio/gpio{0}".format(gpio)):
                open("/sys/class/gpio/export", "w").write(gpio)
            open("/sys/class/gpio/gpio{0}/direction".format(gpio), "w").write("in")

    def _sampling(self, fan_index):
        samples = dict()

        sampling_start_time = int(round(time.time() * 1000))
        for x in range(0, self.sampling_times):
            samples[x] = open("/sys/class/gpio/gpio{0}/value".format(FAN_GPIO[fan_index]), "r").read()
            # print(a[x])
        sampling_end_time = int(round(time.time() * 1000))

#        print("Time=", sampling_end_time - sampling_start_time, "ms")
        tick_time = (sampling_end_time - sampling_start_time) / self.sampling_times
#        print("Tick Time=", tick_time, "ms")

        return [samples, tick_time]

    def get_fanspeed_rpm(self, fan_index):
        samples, tick_time = self._sampling(fan_index)

        start_flag = False

        low_time_length = 0
        high_time_length = 0
        low_time_counter = 0
        high_time_counter = 0

        for x in range(0, self.sampling_times - 1):
            if not start_flag:
                if samples[x] != samples[x + 1] and samples[x + 1] == "0\n":
                    start_flag = True
                    # print("start at ", x)
            else:
                if '0' in samples[x]:
                    low_time_length += 1
                else:
                    high_time_length += 1

                if samples[x] != samples[x + 1]:
                    if '0' in samples[x]:
                        low_time_counter += 1
                    else:
                        high_time_counter += 1

        try:
            average_high_time_length = high_time_length / high_time_counter
        except ZeroDivisionError:
            average_high_time_length = 0
        try:
            average_low_time_length = low_time_length / low_time_counter
        except ZeroDivisionError:
            average_low_time_length = 0

#        print("average high time = {0} ({1}ms)".format(average_high_time_length,
#                                                       average_high_time_length * tick_time))
#        print("average low time = {0} ({1}ms)".format(average_low_time_length,
#                                                      average_low_time_length * tick_time))

        average_time = (average_high_time_length + average_low_time_length) / 2 * tick_time
        try:
            rpm = 15000 / average_time
        except ZeroDivisionError:
            rpm = 0
#        print("Fanspeed is {0} RPM".format(rpm))
        return rpm


if __name__ == "__main__":
    fan_index = sys.argv[1]
    print(f'Fan Index = {fan_index}')
    fanspeed_detector = FanSpeedDetector()
    fanspeed_detected = fanspeed_detector.get_fanspeed_rpm(int(fan_index) - 1)
    print(f'PWM{fan_index} = {fanspeed_detected}')
#    for fan_index in range(0, 4):
#        fanspeed_detected = fanspeed_detected + fanspeed_detector.get_fanspeed_rpm(fan_index).__str__() + '\n'
#        print(f'PWM{fan_index+1} = {fanspeed_detector.get_fanspeed_rpm(fan_index)}')
#    print(fanspeed_detected)
#    with open(OUTPUT_FILE, 'w') as f:
#        f.writelines(fanspeed_detected)

