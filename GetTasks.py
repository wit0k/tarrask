"""
#License

The GetTasks tool is copyright (c) Witold Lawacz (wit0k)

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""
import codecs
import argparse
from binascii import hexlify
from os.path import abspath, dirname, join

VERSION = '0.1'
NAME = 'GetTasks'

class task_scheduler(object):

    input_file = None
    output_file = None
    out_dir = None
    debug = None
    dump_task = None
    out_csv = None

    MAX_TASK_BUFFER_SIZE = 1024
    task_hex_sig = b'\x4e\x00\x54\x00\x20\x00\x54\x00\x41\x00\x53\x00\x4b\x00\x5c\x00'

    def __init__(self, input_file:str, output_file=None, out_dir=None, debug=False, dump_task=False, out_csv=False):

        if '-|-' in input_file:
            self.input_file = [abspath(param) for param in input_file.split('"|"')]
        else:
            self.input_file = self.input_file = [abspath(input_file)]

        self.debug = debug
        self.dump_task = dump_task

        if output_file is None:
            self.output_file = '%s.csv' % self.input_file[0]
        else:
            self.output_file = abspath(output_file)

        self.out_csv = out_csv

        if out_dir is None:
            self.out_dir = dirname(self.input_file[0])
        else:
            self.out_dir = abspath(out_dir)

    def scan_tasks(self, task_name='*'):

        # grep -Poa "N.T. .T.A.S.K.\\\.*?\x00\x00" svchost.exe.dmp | sort -u
        base_sig_pos = 0

        print('[#] Tool to process Task Scheduler svchost dump (Pull Scheduled Tasks and associated Commands)')
        print(' [+] Settings: ')
        print('   [-] Input DUMP(s):')
        for input_file in self.input_file:
            print('     [-] %s' % input_file)

        print('   [-] Export Task to CSV: %s' % ('True' if self.out_csv else 'False'))
        if self.out_csv: print('   [-] Output CSV: %s' % self.output_file if self.out_csv else 'False')
        print('   [-] Dump Task buffer: %s' % ('True' if self.dump_task else 'False'))
        if self.dump_task: print('   [-] Output dir: %s' % self.out_dir)

        for input_file in self.input_file:
            print(' [+] Processing dump file: %s' % input_file)
            with open(input_file, 'rb') as dump_file:

                copy_of_dump_buffer = dump_file.read()

                if '-|-' in task_name:
                    task_names = [param for param in task_name.split('-|-')]
                else:
                    task_names = [task_name]

                for task_name in task_names:

                    look_for_next_sig = True
                    dump_buffer = copy_of_dump_buffer

                    # Encode searched task name (user input)
                    if task_name:
                        task_name = codecs.encode('%s' % task_name, encoding='utf-16-le')
                    else:
                        task_name = codecs.encode('%s' % '*', encoding='utf-16-le')

                    print('   [-] Task to lookup: %s' % task_name)

                    while look_for_next_sig:
                        sig_pos = None
                        sig_pos = dump_buffer.find(self.task_hex_sig)

                        if sig_pos != -1:
                            # Find next occurrence of task's signature
                            next_sig_pos = dump_buffer[sig_pos + 2:].find(self.task_hex_sig)

                            # Prevent Task in Task scenario, or to big buffers (not ideal, but works)
                            if next_sig_pos > self.MAX_TASK_BUFFER_SIZE:
                                next_sig_pos = sig_pos + self.MAX_TASK_BUFFER_SIZE
                            else:
                                next_sig_pos = sig_pos + next_sig_pos

                            # Narrow down task size
                            task_buffer = dump_buffer[sig_pos:next_sig_pos]
                            base_sig_pos += sig_pos
                            dump_buffer = dump_buffer[sig_pos + 1:]

                            # Add possibility to search for all or a given task name
                            if task_name == b'*\x00' or task_name in task_buffer:

                                # Clear variables
                                task_path = 'None'.encode('utf16')
                                task_program = 'None'.encode('utf16')
                                task_program_start_pos = None
                                task_program_params = 'None'.encode('utf16')

                                # Get Task Path ending position
                                task_path_end_pos = task_buffer.find(b'\x00\x00') + 1

                                # Skip broken entries (Sometimes you might encounter memory chunks with valid sid, but without bytes that follow up)
                                if task_path_end_pos != 0:
                                    # Get the Path of the tasks (as it appears in registry)
                                    task_path = task_buffer[0:task_path_end_pos]
                                    task_path = task_path[
                                                task_path.find(b'\x5C\x00'):]  # Strip N.T. .T.A.S.K. by starting from \

                                    # Get End of Task buffer, and strip unnecessary bytes
                                    end_pos = task_buffer.rfind(b'\xFF\xFF\xFF\xFF')

                                    # Narrow the buffer size even more
                                    task_buffer = task_buffer[:end_pos]

                                    # Get task's program starting position (the marker below appears just before the program)
                                    program_marker = b'\x31\x00\x00\x00\x00\x00\x00\x00' # b'\x01\x00\x00\x31\x00\x00\x00\x00\x00\x00\x00'
                                    task_program_start_pos = task_buffer.rfind(program_marker) + len(
                                        program_marker) if task_buffer.rfind(program_marker) != -1 else None

                                    # Sometimes Tasks have no program configured, hence set default value, and skip processing
                                    if task_program_start_pos is None:
                                        task_program = 'None'.encode('utf16')
                                    else:
                                        # Get task's program end position, and pull program
                                        task_program_end_pos = task_buffer[task_program_start_pos:].find(b'\x00\x00')
                                        task_program = task_buffer[
                                                       task_program_start_pos:task_program_start_pos + task_program_end_pos]

                                        cur_pos = task_program_start_pos + task_program_end_pos
                                        # Align with Null byte
                                        if task_program[:-1] != b'\x00':
                                            task_program = task_program + b'\x00'

                                        # Continue only when a task has a program configured
                                        if task_program != b'\x00':
                                            # Get Program params
                                            # Issue: The program is repeated several times, and occurrence count is not the same for each tasks
                                            # - Solution: I found that the last occurrence of program preceded with 2 NULL bytes,
                                            # seems to always appear before the last occurrence of program, followed by program parameters
                                            task_program_params_start_pos = task_buffer[cur_pos:].rfind(
                                                b'\x00\x00' + task_program)

                                            # Skip processing if no parameters found
                                            if task_program_params_start_pos != -1:
                                                cur_pos = cur_pos + task_program_params_start_pos + 2  # Skip first 2 NULL bytes
                                                task_program_params_end_pos = task_buffer[cur_pos:].find(b'\x00\x00')
                                                task_program_params = task_buffer[
                                                                      cur_pos:cur_pos + task_program_params_end_pos + 2]
                                            else:
                                                task_program_params = 'None'.encode('utf16')
                                        else:
                                            task_program = 'None'.encode('utf16')

                                    if self.debug:
                                        print('[Base Offset: %d / Relative: %s] -> TASK: %s\n'
                                              ' -- Size: %s\n '
                                              ' -- Path: %s\n'
                                              ' -- Path(hex): %s\n'
                                              ' -- Program: %s\n'
                                              ' -- Program(hex): %s\n'
                                              ' -- Action: %s\n'
                                              ' -- Action(hex): %s' % (
                                                  base_sig_pos, sig_pos,
                                                  task_buffer.decode('utf16', errors='ignore').replace('\n', ''),
                                                  len(task_buffer),
                                                  task_path.decode('utf16', errors='ignore'),
                                                  hexlify(task_path),
                                                  task_program.decode('utf16', errors='ignore'),
                                                  hexlify(task_program),
                                                  task_program_params.decode('utf16', errors='ignore'),
                                                  hexlify(task_program_params))
                                              )

                                    # Append CSV file
                                    if self.out_csv:
                                        csv_row = '%s;%s;%s\n' % (
                                            'Task_Offset_%s-%s' % (base_sig_pos, sig_pos),
                                            task_path.decode('utf16', errors='ignore'),
                                            task_program_params.decode('utf16', errors='ignore'),
                                        )
                                        with open(self.output_file, 'a') as tasks_csv:
                                            tasks_csv.write(csv_row)

                                    if self.dump_task:
                                        with open(join(self.out_dir, '%s_%s.bin' % (base_sig_pos, sig_pos)), 'wb') as task_dump:
                                            task_dump.write(task_buffer)

                        else:
                            look_for_next_sig = False
                            print('[#] Processing END')

def main(argv=None):

    parser = argparse.ArgumentParser(description="Tool to process Task Scheduler svchost dump (Pull Scheduled Tasks and associated Commands)")
    parser.add_argument("-i", type=str, dest="input_file", required=True, help='Path to process memory dump file')
    parser.add_argument("-f", type=str, dest="out_dir", required=False, default=None, help="Output directory where dumped tasks are stored")
    parser.add_argument("-o", type=str, dest="output_file", required=False, default=None, help="CSV file path")
    parser.add_argument("-n", type=str, dest="task_name", required=False, help='Task name (or names delimited by "-|-") or * to search all tasks', default='*')
    parser.add_argument("-d", "--dump-tasks", dest="dump_task", action="store_true", required=False, default=False, help="Dump Task buffer")
    parser.add_argument("--csv", dest="out_csv", action="store_true", required=False, default=False, help="Dump Task Info to a CSV file indicated in -o")
    parser.add_argument("-v", "--verbose", dest="debug", action="store_true", default=False, help="Enable Debug mode/Verbose mode")
    args = parser.parse_args()

    #Get Task Scheduler object
    task_scheduler_obj = task_scheduler(input_file=args.input_file, output_file=args.output_file,
                                        out_dir=args.out_dir, debug=args.debug, dump_task=args.dump_task, out_csv=args.out_csv)

    # Scan for Task entries in process memory
    task_scheduler_obj.scan_tasks(task_name=args.task_name)

if __name__ == "__main__":
    exit(main())